package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type CompileTarget struct {
	OS        string
	Arch      string
	Transport string
	ServerURL string
}

type CompileResult struct {
	OutputPath string
	Size       int64
	Hash       string
}

func CompileImplant(target CompileTarget, implantDir string) (*CompileResult, error) {
	rustTarget := rustTargetTriple(target.OS, target.Arch)
	env := os.Environ()
	env = append(env,
		fmt.Sprintf("DAGGER_SERVER=%s", target.ServerURL),
		fmt.Sprintf("DAGGER_TRANSPORT=%s", target.Transport),
	)

	cmd := exec.Command("cargo", "build", "--release",
		"--target", rustTarget,
		"--manifest-path", filepath.Join(implantDir, "Cargo.toml"),
	)
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cargo build: %w", err)
	}

	outputPath := filepath.Join(implantDir, "target", rustTarget, "release", "dagger_implant")
	if target.OS == "windows" {
		outputPath += ".exe"
	}

	info, err := os.Stat(outputPath)
	if err != nil {
		return nil, fmt.Errorf("stat output: %w", err)
	}

	return &CompileResult{OutputPath: outputPath, Size: info.Size()}, nil
}

func rustTargetTriple(osName, arch string) string {
	switch {
	case osName == "windows" && arch == "x86_64":
		return "x86_64-pc-windows-msvc"
	case osName == "linux" && arch == "x86_64":
		return "x86_64-unknown-linux-gnu"
	case osName == "linux" && arch == "aarch64":
		return "aarch64-unknown-linux-gnu"
	default:
		return fmt.Sprintf("%s-unknown-%s", arch, osName)
	}
}
