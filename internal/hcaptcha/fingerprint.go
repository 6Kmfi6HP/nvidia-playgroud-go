// Package hcaptcha builds hCaptcha solver fingerprints and orchestrates the
// in-process pipeline: checksiteconfig challenge -> PoW JWT parse -> fingerprint
// JSON -> hsw (V8) solve. No browser is involved.
package hcaptcha

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"glm52-nvidia/internal/hcaptchapow"
)

// AssetBase is where hCaptcha serves challenge assets and hsw.js bundles; the
// fingerprint proof_spec._location is built from it plus the JWT "l" claim.
const AssetBase = "https://newassets.hcaptcha.com"

// fpTemplate mirrors the reference fingerprint shape (fp_build.go in
// Implex-ltd/hcaptcha-reverse): proof_spec + rand + components +
// fingerprint_events + stamp + misc fields.
//
// Field provenance for phase 1:
//
//   - proof_spec.difficulty, .data and ._location come from the challenge
//     JWT: pow.Difficulty (claim s), pow.PowData (claim d) and pow.Location
//     (claim l, normalized onto AssetBase; see locationURL).
//     fingerprint_type, _type and timeout_value are the template's statics.
//   - navigator/screen/fonts/webgl/audio/performance measurements and the
//     "events" (fingerprint_events), suspicious_events, stack_data and perf
//     arrays are the template's static sample values verbatim; a real
//     fingerprint script would collect them at runtime.
//   - web_gl_hash, audio_hash and webrtc_hash stay "-1" (hCaptcha's sentinel
//     for "collection unavailable", identical to a real headless page).
//   - canvas_hash, parent_win_hash and performance_hash are hash-class
//     fields: the reference hashes raw collected content with xxh3. Phase 1
//     has no browser data, so they are computed deterministically with
//     hcaptchapow.HashString over documented placeholder raw content (see
//     hashRawByField below).
//   - stamp is a real hashcash stamp minted for this challenge with
//     hcaptchapow.MintStamp(uint(pow.Difficulty*2), pow.PowData): the JWT
//     difficulty s is already in half-bits, so *2 is the full leading-zero
//     bit count the stamp must satisfy (s=2 -> 4 bits, negligible cost).
//     The salt is random, so stamps are not byte-reproducible; CheckStamp
//     verifies the leading-zero requirement.
//   - rand's second element is computed with hcaptchapow.RandHash over the
//     final JSON with ",_rand" removed (byte-for-byte CRC-32 integrity check,
//     exactly like the reference builder and the hsw WASM's check).
const fpTemplate = `{"proof_spec":{"difficulty":__DIF__,"fingerprint_type":0,"_type":"w","data":"__DATA__","_location":"__LOCATION__","timeout_value":1000},"rand":[0.960537614638231,_rand],"components":{"navigator":{"user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36","language":"fr-FR","languages":["fr-FR","fr","en-US","en"],"platform":"Win32","max_touch_points":0,"webdriver":false,"notification_query_permission":null,"plugins_undefined":false},"screen":{"color_depth":24,"pixel_depth":24,"width":3440,"height":1440,"avail_width":3440,"avail_height":1392},"device_pixel_ratio":1,"has_session_storage":true,"has_local_storage":true,"has_indexed_db":true,"web_gl_hash":"-1","canvas_hash":"__CANVAS_HASH__","has_touch":false,"notification_api_permission":"Denied","chrome":true,"to_string_length":33,"err_firefox":null,"r_bot_score":0,"r_bot_score_suspicious_keys":[],"r_bot_score_2":0,"audio_hash":"-1","extensions":[false],"parent_win_hash":"__PARENT_WIN_HASH__","webrtc_hash":"-1","performance_hash":"__PERF_HASH__","unique_keys":"1,unisat,hcaptcha,onSuccess,grecaptcha,0,onExpire","inv_unique_keys":"__wdata,_sharedLibs,image_label_binary,hsw,image_label_area_select","common_keys_hash":2614578394,"common_keys_tail":"stop,structuredClone,webkitCancelAnimationFrame,webkitRequestAnimationFrame,chrome,fence,caches,cookieStore,ondevicemotion,ondeviceorientation,ondeviceorientationabsolute,launchQueue,sharedStorage,documentPictureInPicture,getScreenDetails,queryLocalFonts,showDirectoryPicker,showOpenFilePicker,showSaveFilePicker,originAgentCluster,onpagereveal,credentialless,speechSynthesis,onscrollend,webkitRequestFileSystem,webkitResolveLocalFileSystemURL,providers,_phantomHideProvidersArray,_phantomShowMetamaskExplainer,isPhantomInstalled,regeneratorRuntime,SENTRY_RELEASE,web3,Raven,XverseProviders,btc_providers","features":{"performance_entries":true,"web_audio":true,"web_rtc":true,"canvas_2d":true,"fetch":true}},"events":[[2455893439,"\"Europe/Paris\""],[1438349120,"13177607191192652685"],[3227950072,"[24,24,65536,212988,200704]"],[3025237892,"12027682292028963860"],[4165641576,"[32767,32767,16384,8,8,8]"],[91877612,"[[[\"chrome-extension://idnnbdplmphpflfnlkomgpfbpcgelopg/inpage.js\",0,3],[\"https://newassets.hcaptcha.com/captcha/v1/17b82e2/hcaptcha.js\",0,5]],[[\"*\",84,9]]]"],[2252840959,"11079656286779448742"],[3487278513,"1135"],[2005859105,"[2147483647,2147483647,4294967294]"],[4272905495,"31.25000000745058"],[188652528,"[16,4095,30,16,16380,120,12,120,[23,127,127]]"],[2062697704,"[[277114314453,277114314460,277114314451,357114314456,277114314452,554228628898,57114314443,717114314371391,554228628897,277114314456,1108457257862,277114314450,554228628919,277114314460,277114314451],false]"],[1325100515,"true"],[1268522788,"[16384,32,16384,2048,2,2048]"],[1108939890,"[\"Europe/Paris\",-60,-60,-3203647761000,\"heure normale d’Europe centrale\",\"fr\"]"],[1579262840,"[-6.172840118408203,-20.710678100585938,120.71067810058594,-20.710678100585938,141.42135620117188,120.71067810058594,-20.710678100585938,141.42135620117188,-20.710678100585938,-20.710678100585938,0,0,320,490,true]"],[2158825350,"[1,1024,1,1,4]"],[2509526170,"[2147483647,2147483647,2147483647,2147483647]"],[28433086,"16.400000005960464"],[2284058841,"40224"],[522949833,"[\"QzM1IjN5gzMYCDMX\",\"c\",\"1\",\"XAWOPPOCYTLBS\"]"],[2150450975,"16132118391739044799"],[2228825458,"1712155469384.5"],[639595872,"1444582"],[3197530747,"[3440,1440,3440,1392,24,24,false,0,1,2353,1399,true,true,true,false]"],[930901639,"41.70000000298023"],[3095117296,"[\"5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\",\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36\",8,16,\"fr-FR\",[\"fr-FR\",\"fr\",\"en-US\",\"en\"],\"Win32\",null,[\"Google Chrome 123\",\"Not:A-Brand 8\",\"Chromium 123\"],false,\"Windows\",2,5,true,false,0,false,false,true,\"[object Keyboard]\",false,false]"],[2545605315,"[[\"LwitJG5mBmTGZo0uvinesalCMYuCsTJm\",\"19\",\"13\",\"TUEENBUIKYSVN\"],[\"VQoLKtgnKmLajmLY0umfLS=K0mJftmPajmLuHeFVZXwmKmLajmLEgeFVZXwajmLKKb3PgA5ntSxEDmyuCkwmgmwaDmyQDo5KCmyuSWUBjmLmDm2aDmyuyVznEmyuCtqTEd3hMAwItJtfKtJ5KRwItJOm\",\"5\",\"82\",\"KLMGOTNTZAUFP\"]]"],[3467501445,"57"],[262879291,"8398791803026140725"],[3570513324,"4631229088072584217"],[3235903591,"[[true,\"fr-FR\",true,\"Microsoft Hortense - French (France)\",\"Microsoft Hortense - French (France)\"],[false,\"fr-FR\",true,\"Microsoft Julie - French (France)\",\"Microsoft Julie - French (France)\"],[false,\"fr-FR\",true,\"Microsoft Paul - French (France)\",\"Microsoft Paul - French (France)\"]]"],[1019203231,"[[\"loadTimes\",\"csi\",\"app\"],35,34,null,false,false,true,37,true,true,true,true,true,[\"providers\",\"_phantomHideProvidersArray\",\"_phantomShowMetamaskExplainer\",\"isPhantomInstalled\",\"regeneratorRuntime\",\"SENTRY_RELEASE\",\"web3\",\"Raven\",\"_sharedLibs\",\"XverseProviders\",\"btc_providers\",\"hsw\",\"__wdata\",\"image_label_area_select\",\"image_label_binary\",\"ethereum\",\"phantom\",\"solana\",\"rabby\",\"rabbyWalletRouter\",\"StacksProvider\",\"BitcoinProvider\"],[[\"getElementsByClassName\",[]],[\"getElementById\",[]],[\"querySelector\",[]],[\"querySelectorAll\",[]]],[],true]"],[2840639612,"[1,4,5,7,9,12,20,21,24,25,29,31]"],[1538111826,"17157476241021694346"],[4250147733,"15307345790125003576"],[2963547975,"[16,1024,4096,7,12,120,[23,127,127]]"],[1007274290,"9345374751420407194"],[2772590518,"[\"Google Inc. (NVIDIA)\",\"ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Ti (0x00002489) Direct3D11 vs_5_0 ps_5_0, D3D11)\"]"],[104149656,"[0,1,2,3,4]"],[4173238370,"[[\"img:imgs3.hcaptcha.com\",0,25.55000000447035],[\"navigation:newassets.hcaptcha.com\",19.80000001192093,33.29999999701977],[\"script:newassets.hcaptcha.com\",16.25000000745058,29.899999998509884],[\"xmlhttprequest:api.hcaptcha.com\",0,204.59999999403954]]"],[1177832592,"[143526983270,143526983270,null,null,4294705152,true,true,true,null]"],[2163086961,"412.09999999403954"],[2416260428,"4932383211497360507"],[2444509564,"[\"Windows\",\"15.0.0\",null,\"64\",\"x86\",\"123.0.6312.86\"]"],[611315898,"8915205951503093450"],[850956849,"2944899007327630659"],[728511561,"4807243413252001311"],[1668959119,"631"],[1246555942,"[17]"],[3197521464,"18207788058829391080"],[1826871708,"[[221,[221,221,221,255,221,221,221,255,221,221,221,255,221,221,221,255]],[[11,0,0,95.96875,15,4,96.765625],[[12,0,-1,113.125,17,4,113],[11,0,0,111,12,4,111],[11,0,0,95.96875,15,4,96.765625],[11,0,0,95.96875,15,4,96.765625],[11,0,0,95.96875,15,4,96.765625],[11,0,0,95.96875,15,4,96.765625],[11,0,0,95.96875,15,4,96.765625],[11,0,0,95.96875,15,4,96.765625],[12,0,0,109.640625,14,3,110.1953125]]],[0,2,8,13,15,17,24,26,27,28,29,30,31,32,34,37,39,40,49,69,75,76,79,80],[0,0,0,0,14,3,0]]"],[2970644973,"[\"va6FXY=00Y6DHetZkmlG\",\"8\",\"e\",\"ORGCVWSNOSDMJ\"]"],[2620085432,"[4,120,4]"],[2974784595,"[0,10465,10465]"]],"suspicious_events":[],"messages":null,"stack_data":["Array.reduce (<anonymous>)\nonMessage (chrome-extension://gppongmhjkpfnbhagpmjfkannfbllamg/js/dom.js)","new Promise (<anonymous>)"],"stamp":"__STAMP__","href":"https://accounts.hcaptcha.com/demo","ardata":null,"errs":{"list":[]},"perf":[[1,6],[2,416]]}`

// hashRawByField is the static raw content that hash-class component fields
// stand in for. Phase 1 ships no browser collection, so each field hashes a
// fixed placeholder byte string; the values are deterministic and marked as
// such in the produced fingerprint (swap in real collected raw bytes later
// without changing the field wiring).
var hashRawByField = map[string][]byte{
	"canvas_hash":      []byte("hcaptcha-phase1-canvas-placeholder"),
	"parent_win_hash":  []byte("hcaptcha-phase1-parent-window-placeholder"),
	"performance_hash": []byte("hcaptcha-phase1-performance-placeholder"),
}

// Template segments: the template is split once at the placeholder
// boundaries so each fingerprint build assembles parts into one buffer
// instead of running seven full-template ReplaceAll passes (~70KB of
// transient garbage per solve under load).
var (
	segBeforeDif   string // up to __DIF__
	segDifToData   string // __DIF__ .. __DATA__
	segDataToLoc   string // __DATA__ .. __LOCATION__
	segLocToRand   string // __LOCATION__ .. "_rand" (hash placeholders already substituted; ends after the comma)
	segRandToStamp string // after rand float .. __STAMP__
	segAfterRand   string // after __STAMP__ to the end
)

// hashVals are the deterministic component hashes; the placeholders inside
// segLocToStamp were substituted at init.
var hashVals = map[string]string{}

func init() {
	tpl := fpTemplate
	for _, f := range []string{"canvas_hash", "parent_win_hash", "performance_hash"} {
		hashVals[f] = hcaptchapow.HashString(hashRawByField[f])
		tpl = strings.ReplaceAll(tpl, placeholderFor(f), hashVals[f])
	}

	var rest string
	segBeforeDif, rest = cut2(tpl, "__DIF__")
	segDifToData, rest = cut2(rest, "__DATA__")
	segDataToLoc, rest = cut2(rest, "__LOCATION__")
	// Between __LOCATION__ and the rand element the hash placeholders have
	// already been substituted above, so this segment is fully static.
	segLocToRand, rest = cut2(rest, "_rand")
	segRandToStamp, segAfterRand = cut2(rest, "__STAMP__")
}

func cut2(s, placeholder string) (before, after string) {
	i := strings.Index(s, placeholder)
	if i < 0 {
		panic("hcaptcha: fingerprint template missing placeholder " + placeholder)
	}
	return s[:i], s[i+len(placeholder):]
}

func placeholderFor(field string) string {
	switch field {
	case "canvas_hash":
		return "__CANVAS_HASH__"
	case "parent_win_hash":
		return "__PARENT_WIN_HASH__"
	case "performance_hash":
		return "__PERF_HASH__"
	}
	return ""
}

// fpBufPool recycles fingerprint assembly buffers across solves.
var fpBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 12288)
		return &b
	},
}

// BuildFingerprint renders the hCaptcha fingerprint JSON for the challenge
// described by pow: proof_spec fields from the JWT (difficulty/data/location),
// static sample components and fingerprint_events, deterministic xxh3 hash
// fields and a self-consistent rand element. It returns the fingerprint
// standard-base64 encoded, the form the hsw WASM consumes.
func BuildFingerprint(pow *hcaptchapow.Pow) (string, error) {
	if pow == nil || pow.PowData == "" || pow.Location == "" {
		return "", fmt.Errorf("hcaptcha: fingerprint: pow missing data/location")
	}

	stamp, err := hcaptchapow.MintStamp(uint(pow.Difficulty*2), pow.PowData)
	if err != nil {
		return "", fmt.Errorf("hcaptcha: fingerprint: mint stamp: %w", err)
	}

	bufp := fpBufPool.Get().(*[]byte)
	buf := (*bufp)[:0]
	buf = append(buf, segBeforeDif...)
	buf = strconv.AppendFloat(buf, pow.Difficulty, 'f', -1, 64)
	buf = append(buf, segDifToData...)
	buf = append(buf, pow.PowData...)
	buf = append(buf, segDataToLoc...)
	buf = append(buf, locationURL(pow.Location)...)
	buf = append(buf, segLocToRand...) // ends with "," right before the rand float

	// CRC-32 over the payload with the second rand element removed, exactly
	// as the reference builder computes it before splicing the float back in:
	// everything built so far (through the comma) + "]" + the tail with the
	// stamp substituted. Built in a second pooled buffer; the main buffer is
	// untouched.
	crcp := fpBufPool.Get().(*[]byte)
	crcBuf := (*crcp)[:0]
	// ",_rand" is removed entirely: rand[0]'s closing bracket comes from the
	// tail segment itself (segRandToStamp starts with "]").
	crcBuf = append(crcBuf, buf[:len(buf)-1]...)
	crcBuf = append(crcBuf, segRandToStamp...)
	crcBuf = append(crcBuf, stamp...)
	crcBuf = append(crcBuf, segAfterRand...)
	_, randVal := hcaptchapow.RandHash(crcBuf)
	*crcp = crcBuf[:0]
	fpBufPool.Put(crcp)

	buf = strconv.AppendFloat(buf, randVal, 'f', -1, 64)
	buf = append(buf, segRandToStamp...)
	buf = append(buf, stamp...)
	buf = append(buf, segAfterRand...)

	if !json.Valid(buf) {
		*bufp = buf[:0]
		fpBufPool.Put(bufp)
		return "", fmt.Errorf("hcaptcha: fingerprint: produced invalid JSON")
	}
	out := make([]byte, base64.StdEncoding.EncodedLen(len(buf)))
	base64.StdEncoding.Encode(out, buf)
	*bufp = buf[:0]
	fpBufPool.Put(bufp)
	return string(out), nil
}

// locationURL normalizes the JWT "l" claim into the absolute asset URL used
// for proof_spec._location. Older payloads carry the full URL, current ones
// a path like "/c/<sha256>", legacy checksiteconfig bodies a bare bundle id:
//
//	"https://newassets.hcaptcha.com/c/282d0ff" -> unchanged
//	"/c/282d0ff"                              -> "https://newassets.hcaptcha.com/c/282d0ff"
//	"282d0ff"                                 -> "https://newassets.hcaptcha.com/c/282d0ff"
//
// hsw.AssetURL follows the same conventions for the hsw.js download.
func locationURL(loc string) string {
	loc = strings.TrimSuffix(loc, "/")
	switch {
	case strings.HasPrefix(loc, "http://"), strings.HasPrefix(loc, "https://"):
		return loc
	case strings.HasPrefix(loc, "/"):
		return AssetBase + loc
	default:
		return AssetBase + "/c/" + loc
	}
}
