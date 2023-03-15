package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"

	"github.com/docker/distribution/reference"
	"github.com/docker/docker/pkg/idtools"
	controlapi "github.com/moby/buildkit/api/services/control"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/moby/pkg/jsonmessage"

	"github.com/moby/moby/registry"

	clibuild "github.com/docker/cli/cli/command/image/build"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	"github.com/docker/cli/cli/config/credentials"
	"github.com/docker/docker/api/types"
	cliclient "github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
)

func main() {

	fmt.Printf("Called with args %#+v\n", os.Args)

	imageName := os.Args[1]
	contextDir := os.Args[2]

	ctx := context.Background()

	contextDir, err := clibuild.ResolveAndValidateContextPath(contextDir)
	if err != nil {
		panic(fmt.Errorf("error resolving context: %w", err))
	}

	if err := clibuild.ValidateContextDirectory(contextDir, nil); err != nil {
		panic(fmt.Errorf("error validating context: %w", err))
	}

	tar, err := archive.TarWithOptions(contextDir, &archive.TarOptions{
		ChownOpts: &idtools.Identity{UID: 0, GID: 0},
	})
	if err != nil {
		panic(fmt.Errorf("error archiving context as tar: %w", err))
	}

	cfg, err := getDefaultDockerConfig()
	if err != nil {
		panic(fmt.Errorf("error getting default docker config: %w", err))
	}

	authConfigs := make(map[string]types.AuthConfig)

	auths, err := cfg.GetAllCredentials()
	if err != nil {
		panic(fmt.Errorf("error getting credentials: %w", err))
	}
	for k, auth := range auths {
		authConfigs[k] = types.AuthConfig(auth)
	}

	docker, err := cliclient.NewClientWithOpts(
		cliclient.FromEnv,
		cliclient.WithAPIVersionNegotiation(),
	)
	sharedKey := getBuildSharedKey(contextDir)
	sess, err := session.NewSession(ctx, "pulumi-docker", sharedKey)
	if err != nil {
		panic(fmt.Errorf("error starting new session: %w", err))
	}
	dockerAuthProvider := authprovider.NewDockerAuthProvider(cfg)
	sess.Allow(dockerAuthProvider)

	dialSession := func(ctx context.Context, proto string, meta map[string][]string) (net.Conn, error) {
		return docker.DialHijack(ctx, "/session", proto, meta)
	}
	go func() {
		err := sess.Run(ctx, dialSession)
		if err != nil {
			return
		}
	}()
	defer sess.Close()
	sessId := sess.ID()
	// opts.BuildID = stringid.GenerateRandomID()

	opts := types.ImageBuildOptions{
		Tags:        []string{imageName},
		Dockerfile:  "Dockerfile",
		Platform:    "linux/amd64",
		Version:     types.BuilderBuildKit,
		AuthConfigs: authConfigs,
		CacheFrom:   []string{imageName},
		BuildArgs: map[string]*string{
			"BUILDKIT_INLINE_CACHE": asPtr("1"),
		},
		SessionID: sessId,
	}

	imgBuildResp, err := docker.ImageBuild(ctx, tar, opts)
	if err != nil {
		panic(fmt.Errorf("error calling Docker ImageBuild RPC: %w", err))
	}
	defer imgBuildResp.Body.Close()

	// Print build logs to `Info` progress report
	scanner := bufio.NewScanner(imgBuildResp.Body)
	for scanner.Scan() {
		info, err := processLogLine(scanner.Text())
		if err != nil {
			panic(fmt.Errorf("error processing build: %w", err))
		}
		fmt.Println(info)
	}

	ref, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		panic(fmt.Errorf("error parsing image name: %w", err))
	}
	// Resolve the Repository name from fqn to RepositoryInfo
	hostname := reference.Domain(ref)
	switch hostname {
	// handle historically permitted names, mapping them to the v1 registry hostname
	case registry.IndexHostname, registry.IndexName, registry.DefaultV2Registry.Host:
		hostname = registry.IndexServer
	}
	registryAuth, err := cfg.GetAuthConfig(hostname)
	if err != nil {
		panic(fmt.Errorf("error getting auth config: %w", err))
	}
	authConfigBytes, err := json.Marshal(registryAuth)
	if err != nil {
		panic(fmt.Errorf("error marshaling authConfig: %v", err))
	}
	authConfigEncoded := base64.URLEncoding.EncodeToString(authConfigBytes)

	pushOutput, err := docker.ImagePush(ctx, imageName, types.ImagePushOptions{RegistryAuth: authConfigEncoded})
	if err != nil {
		panic(fmt.Errorf("error calling Docker ImagePush RPC: %w", err))
	}
	defer pushOutput.Close()

	pushScanner := bufio.NewScanner(pushOutput)
	for pushScanner.Scan() {
		info, err := processLogLine(pushScanner.Text())
		if err != nil {
			panic(fmt.Errorf("error processing push: %w", err))
		}
		fmt.Println(info)
	}

	fmt.Printf("Successfully pushed image.")
}

func asPtr[T any](t T) *T {
	return &t
}

func getDefaultDockerConfig() (*configfile.ConfigFile, error) {
	cfg, err := config.Load(config.Dir())
	if err != nil {
		return nil, err
	}
	cfg.CredentialsStore = credentials.DetectDefaultStore(cfg.CredentialsStore)
	return cfg, nil
}

func getBuildSharedKey(dir string) string {
	// build session is hash of build dir with node based randomness
	s := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", tryNodeIdentifier(), dir)))
	return hex.EncodeToString(s[:])
}

func tryNodeIdentifier() string {
	out := config.Dir() // return config dir as default on permission error
	if err := os.MkdirAll(config.Dir(), 0700); err == nil {
		sessionFile := filepath.Join(config.Dir(), ".buildNodeID")
		if _, err := os.Lstat(sessionFile); err != nil {
			if os.IsNotExist(err) { // create a new file with stored randomness
				b := make([]byte, 32)
				if _, err := rand.Read(b); err != nil {
					return out
				}
				if err := ioutil.WriteFile(sessionFile, []byte(hex.EncodeToString(b)), 0600); err != nil {
					return out
				}
			}
		}

		dt, err := ioutil.ReadFile(sessionFile)
		if err == nil {
			return string(dt)
		}
	}
	return out
}

func processLogLine(msg string) (string, error) {
	var info string
	var jm jsonmessage.JSONMessage
	err := json.Unmarshal([]byte(msg), &jm)
	if err != nil {
		return info, fmt.Errorf("encountered error unmarshalling: %v", err)
	}
	// process this JSONMessage
	if jm.Error != nil {
		if jm.Error.Code == 401 {
			return info, fmt.Errorf("authentication is required")
		}
		if jm.Error.Message == "EOF" {
			return info, fmt.Errorf("%s\n: This error is most likely due to incorrect or mismatched registry "+
				"credentials. Please double check you are using the correct credentials and registry name.",
				jm.Error.Message)
		}
		return info, fmt.Errorf(jm.Error.Message)
	}
	if jm.From != "" {
		info += jm.From
	}
	if jm.Progress != nil {
		info += jm.Status + " " + jm.Progress.String()
	} else if jm.Stream != "" {
		info += jm.Stream

	} else {
		info += jm.Status
	}
	if jm.Aux != nil {
		// if we're dealing with buildkit tracer logs, we need to decode
		if jm.ID == "moby.buildkit.trace" {
			// Process the message like the 'tracer.write' method in build_buildkit.go
			// https://github.com/docker/docker-ce/blob/master/components/cli/cli/command/image/build_buildkit.go#L392
			var resp controlapi.StatusResponse
			var infoBytes []byte
			// ignore messages that are not understood
			if err := json.Unmarshal(*jm.Aux, &infoBytes); err != nil {
				info += "failed to parse aux message: " + err.Error()
			}
			if err := (&resp).Unmarshal(infoBytes); err != nil {
				info += "failed to parse aux message: " + err.Error()
			}
			for _, vertex := range resp.Vertexes {
				info += fmt.Sprintf("digest: %+v\n", vertex.Digest)
				info += fmt.Sprintf("%s\n", vertex.Name)
				if vertex.Error != "" {
					info += fmt.Sprintf("error: %s\n", vertex.Error)
				}
			}
			for _, status := range resp.Statuses {
				info += fmt.Sprintf("%s\n", status.GetID())
			}
			for _, log := range resp.Logs {
				info += fmt.Sprintf("%s\n", string(log.Msg))

			}
			for _, warn := range resp.Warnings {
				info += fmt.Sprintf("%s\n", string(warn.Short))
			}

		} else {
			// most other aux messages are secretly a BuildResult
			var result types.BuildResult
			if err := json.Unmarshal(*jm.Aux, &result); err != nil {
				// in the case of non-BuildResult aux messages we print out the whole object.
				infoBytes, err := json.Marshal(jm.Aux)
				if err != nil {
					info += "failed to parse aux message: " + err.Error()
				}
				info += string(infoBytes)
			} else {
				info += result.ID
			}
		}
	}
	return info, nil
}
