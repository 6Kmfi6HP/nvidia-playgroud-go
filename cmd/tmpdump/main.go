package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"nvidia-playgroud-go/internal/hsw"
)

func main() {
	loc := os.Args[1]
	out := os.Args[2]
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	b, err := hsw.Load(ctx, loc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(out, []byte(b.Source), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Println("dumped", out, "version:", b.Version, "len:", len(b.Source))
}
