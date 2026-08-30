// cmd/example/main.go — Example usage of the glm52 Go client.
//
// Usage:
//
//	# Captcha token mode (reverse-engineered)
//	go run . -captcha "P1_..."
//
//	# Auto-mint captcha token via pure-Go PoW (no manual token needed)
//	go run . -auto
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	glm52 "glm52-nvidia"
)

func main() {
	captcha := flag.String("captcha", "", "hCaptcha token (reverse-engineered mode)")
	auto := flag.Bool("auto", false, "Auto-mint captcha token via pure-Go PoW")
	model := flag.String("model", "", "model id (e.g. deepseek-ai/deepseek-v4-pro-0813); empty = default (moonshotai/kimi-k3)")
	prompt := flag.String("prompt", "Explain the meaning of life in one sentence.", "prompt to send")
	stream := flag.Bool("stream", true, "use streaming")
	smoothMs := flag.Int("smooth-ms", 12, "typewriter delay per rune for stream output (0=off)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	// --- Build client (model + captcha from flags) ---

	var token string
	switch {
	case *auto:
		t, err := extractCaptchaToken(ctx)
		if err != nil {
			log.Fatalf("Failed to auto-extract captcha token: %v", err)
		}
		token = t
		fmt.Printf("✓ Extracted captcha token: %s...\n", token[:30])

	case *captcha != "":
		token = *captcha

	default:
		log.Fatal("Specify -captcha or -auto")
	}

	opts := []glm52.Option{glm52.WithCaptchaToken(token)}
	if *model != "" {
		opts = append(opts, glm52.WithModel(*model))
	}
	client := glm52.New(opts...)

	// --- Send request ---
	messages := []glm52.Message{
		{Role: "system", Content: "You are a helpful assistant."},
		{Role: "user", Content: *prompt},
	}

	if *stream {
		fmt.Print("\n=== Streaming response ===\n\n")
		smooth := time.Duration(*smoothMs) * time.Millisecond
		var lastUsage *glm52.Usage
		var reasoningStarted, contentStarted bool
		err := client.StreamChat(ctx, messages, func(chunk glm52.StreamChunk) {
			if chunk.Error != nil {
				log.Printf("Stream error: %v", chunk.Error)
				return
			}
			if chunk.Reasoning != "" {
				if !reasoningStarted {
					fmt.Print("--- thinking ---\n")
					reasoningStarted = true
				}
				writeSmooth(chunk.Reasoning, smooth)
			}
			if chunk.Content != "" {
				if reasoningStarted && !contentStarted {
					fmt.Print("\n--- answer ---\n")
					contentStarted = true
				}
				writeSmooth(chunk.Content, smooth)
			}
			if chunk.Usage != nil {
				lastUsage = chunk.Usage
			}
		})
		if err != nil {
			log.Fatalf("Stream chat failed: %v", err)
		}
		fmt.Println()
		if lastUsage != nil {
			fmt.Printf("\n[Usage: %s]\n", lastUsage.Format())
		}
	} else {
		resp, err := client.Chat(ctx, messages)
		if err != nil {
			log.Fatalf("Chat failed: %v", err)
		}
		fmt.Print("\n=== Response ===\n\n")
		if len(resp.Choices) > 0 {
			msg := resp.Choices[0].Message
			if msg.ReasoningContent != "" {
				fmt.Printf("--- thinking ---\n%s\n\n--- answer ---\n", msg.ReasoningContent)
			}
			fmt.Println(msg.Content)
		}
		if resp.Usage != nil {
			fmt.Printf("\n[Usage: %s]\n", resp.Usage.Format())
		}
	}
}
