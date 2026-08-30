// AWS WAF challenge.js crypto-config extractor, pure JS (no Node builtins).
// Runs inside the embedded V8 via v8go; the Go side injects the challenge
// script source and reads back the JSON returned by extractConfig.
//
// Ported from kareeen133/AWS-WAF-Solver (MIT) extract_config.js, with an
// extra fallback for identifier built through an object literal
// ({'identifier': decoder(0x..)}) which newer challenge.js bundles use.

function extractFunctionAt(script, startPos) {
    var braceStart = script.indexOf('{', startPos);
    if (braceStart === -1) return null;
    var depth = 0, inString = false, stringChar = '', escaped = false;
    for (var i = braceStart; i < script.length; i++) {
        var ch = script[i];
        if (escaped) { escaped = false; continue; }
        if (ch === '\\') { escaped = true; continue; }
        if (inString) { if (ch === stringChar) inString = false; continue; }
        if (ch === '"' || ch === '\'' || ch === '`') { inString = true; stringChar = ch; continue; }
        if (ch === '/' && i + 1 < script.length) {
            if (script[i + 1] === '/') { while (i < script.length && script[i] !== '\n') i++; continue; }
            if (script[i + 1] === '*') { i += 2; while (i + 1 < script.length && !(script[i] === '*' && script[i + 1] === '/')) i++; i++; continue; }
        }
        if (ch === '{') depth++;
        if (ch === '}') { depth--; if (depth === 0) return script.substring(startPos, i + 1); }
    }
    return null;
}

function extractConfig(script) {
    var arrayNameMatch = script.match(/function\s+(a0_0x[0-9a-f]+)\s*\(\)\s*\{\s*(?:var|let|const)\s+_0x[0-9a-f]+=\[/);
    if (!arrayNameMatch) throw new Error('Could not find global string array function');
    var arrayFuncName = arrayNameMatch[1];

    var decoderNameRe = new RegExp('function\\s+(a0_0x[0-9a-f]+)\\s*\\(\\s*_0x[0-9a-f]+\\s*,\\s*_0x[0-9a-f]+\\s*\\)');
    var decoderNameMatch = script.match(decoderNameRe);
    if (!decoderNameMatch) throw new Error('Could not find decoder function');
    var decoderFuncName = decoderNameMatch[1];

    var arrayFuncCode = extractFunctionAt(script, script.indexOf(arrayNameMatch[0]));
    if (!arrayFuncCode) throw new Error('Failed to extract array function body');

    var decoderFuncStartIdx = script.indexOf(decoderNameMatch[0]);
    var decoderFuncCode = extractFunctionAt(script, decoderFuncStartIdx);
    if (!decoderFuncCode) throw new Error('Failed to extract decoder function body');

    var rotationRe = new RegExp('\\(function\\s*\\(\\s*\\w+\\s*,\\s*\\w+\\s*\\)\\s*\\{' +
        '[\\s\\S]*?push[\\s\\S]*?shift[\\s\\S]*?' +
        '\\}\\)\\s*\\(\\s*' + arrayFuncName + '\\s*,\\s*0x[0-9a-f]+\\s*\\)\\s*;?');
    var rotationMatch = script.match(rotationRe);

    var setupCode = arrayFuncCode + ';\n';
    setupCode += decoderFuncCode + ';\n';
    if (rotationMatch) setupCode += rotationMatch[0] + ';\n';
    setupCode += '\nthis.__decoder = ' + decoderFuncName + ';\n';

    var sandbox = {};
    // emulate vm.runInContext: build a plain function scope
    var runner = new Function(setupCode + '\nreturn this.__decoder;');
    var decoder = runner.call(sandbox);

    if (typeof decoder !== 'function') throw new Error('Decoder is not a function after eval');

    var decoded = new Map();
    for (var i = 0; i < 0x600; i++) {
        try {
            var val = decoder(i);
            if (typeof val === 'string' && val.length > 0) decoded.set(i, val);
        } catch (e) {}
    }

    var aesKey = null;
    for (var idx of decoded.keys()) {
        var val = decoded.get(idx);
        if (/^[0-9a-f]{64}$/.test(val)) { aesKey = val; break; }
    }

    var identifier = null;

    // 1) ['identifier'] = decoder(0x..)
    var idAssignRe = /\['identifier'\]\s*=\s*(\w+)\s*\(\s*0x([0-9a-f]+)/;
    var idAssignMatch = script.match(idAssignRe);
    if (idAssignMatch) {
        var idIdx = parseInt(idAssignMatch[2], 16);
        var directVal = decoded.get(idIdx);
        if (directVal && /^[A-Za-z]/.test(directVal)) identifier = directVal;
    }

    // 2) 'identifier': decoder(0x..) object literal (newer bundles)
    if (!identifier) {
        var objLitRe = /'identifier'\s*:\s*(\w+)\s*\(\s*0x([0-9a-f]+)\s*\)/;
        var objM = script.match(objLitRe);
        if (objM) {
            var oIdx = parseInt(objM[2], 16);
            var oVal = decoded.get(oIdx);
            if (oVal && typeof oVal === 'string') identifier = oVal;
        }
    }

    // 3) aliased decoder assignments
    if (!identifier) {
        var aliasRe = new RegExp('(?:var|let|const)\\s+(\\w+)\\s*=\\s*' + decoderFuncName + '\\b', 'g');
        var aliasMatch;
        var aliases = new Set();
        while ((aliasMatch = aliasRe.exec(script)) !== null) aliases.add(aliasMatch[1]);
        for (var alias of aliases) {
            var re = new RegExp("\\['identifier'\\]\\s*=\\s*" + alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*\\(\\s*0x([0-9a-f]+)');
            var m = script.match(re);
            if (m) {
                var aIdx = parseInt(m[1], 16);
                var aVal = decoded.get(aIdx);
                if (aVal && typeof aVal === 'string') { identifier = aVal; break; }
            }
        }
    }

    // 4) near 'Present' heuristic
    if (!identifier) {
        var presentIdx = -1;
        for (var idx of decoded.keys()) { if (decoded.get(idx) === 'Present') { presentIdx = idx; break; } }
        if (presentIdx >= 0) {
            var jsBuiltins = new Set(['Present','Browser','String','Count','Milliseconds','Object','Array','Function','Error','Number','Boolean','RegExp','Date','Symbol','Promise','Proxy','Map','Set','Uint8Array','ArrayBuffer','TypeError','RangeError','SyntaxError','UNIVERSAL','SEQUENCE','INTEGER','OCTET','BOOLEAN']);
            for (var offset = -20; offset <= 0; offset++) {
                var val2 = decoded.get(presentIdx + offset);
                if (val2 && /^[A-Z][a-z]{1,15}$/.test(val2) && !jsBuiltins.has(val2)) { identifier = val2; break; }
            }
        }
    }

    var typeNames = {};
    var hashRe = /["']h([0-9a-f]{60,})["']/g;
    var hashMatch;
    var hashes = [];
    while ((hashMatch = hashRe.exec(script)) !== null) hashes.push('h' + hashMatch[1]);
    for (var hash of hashes) {
        if (hash.startsWith('ha9faaffd')) typeNames[hash] = 'mp_verify';
        else if (hash.startsWith('h72f957df')) typeNames[hash] = 'verify';
        else if (hash.startsWith('h7b0c470f')) typeNames[hash] = 'verify';
    }

    var signalVersion = null;
    for (var idx of decoded.keys()) {
        var v = decoded.get(idx);
        if (/^\d+\.\d+\.\d+$/.test(v) && v !== '0.1.0') { signalVersion = v; break; }
    }
    if (!signalVersion) {
        var versionLitRe = /['"](\\d+\\.\\d+\\.\\d+)['\"]/g;
        var vMatch;
        while ((vMatch = versionLitRe.exec(script)) !== null) {
            if (vMatch[1] !== '0.1.0') { signalVersion = vMatch[1]; break; }
        }
    }

    return { key: aesKey, identifier: identifier, typeNames: typeNames, signalVersion: signalVersion };
}
