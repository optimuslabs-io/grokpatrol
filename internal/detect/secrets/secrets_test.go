package secrets

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/optimuslabs-io/grokpatrol/internal/engine"
	"github.com/optimuslabs-io/grokpatrol/internal/model"
)

// fixtureRepo builds a throwaway git repo that commits two secrets and then
// deletes them -- the exact shape the incident exfiltrated. The secrets are gone
// from the working tree but still reachable from HEAD, so they were in the
// uploaded object set, and the user cannot see them by looking at their checkout.
func fixtureRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()

	// Author/committer identity and dates are pinned here rather than read from the
	// user's global config, so the fixture never depends on (or touches) it.
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	run("init", "-q", "--initial-branch=main")

	write("README.md", "hello")
	write(".env.production", "DATABASE_URL=postgres://user:hunter2@prod/db")
	write("certs/prod.pem", "-----BEGIN PRIVATE KEY-----")
	write(".env.example", "DATABASE_URL=")
	run("add", "-A")
	run("commit", "-q", "-m", "initial")

	// The critical step: delete them from the checkout. They live on in history.
	run("rm", "-q", ".env.production", "certs/prod.pem")
	run("commit", "-q", "-m", "remove secrets (they remain in history)")

	write("terraform.tfvars", "api_token = \"abc\"")
	run("add", "-A")
	run("commit", "-q", "-m", "add tfvars")

	return dir
}

func runDetector(t *testing.T, repo string, useGit bool) model.RepoStatus {
	t.Helper()
	env := &engine.Env{
		UseGit:        useGit,
		HistoryScope:  "head",
		MaxGitObjects: 1_000_000,
		GitTimeout:    30 * time.Second,
		ExtraRepos:    []string{repo},
	}
	res, err := New().Run(context.Background(), env)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(res.Repos) != 1 {
		t.Fatalf("want 1 repo, got %d", len(res.Repos))
	}
	return res.Repos[0]
}

func hitFor(st model.RepoStatus, path string) *model.SecretHit {
	for i := range st.SecretFiles {
		if st.SecretFiles[i].Path == path {
			return &st.SecretFiles[i]
		}
	}
	return nil
}

// The blob id grokpatrol prints must be one git actually has. The report tells the
// user to run `git cat-file -p <blob>` on it, so an id that resolves to nothing --
// or to the wrong file -- is worse than printing none at all: it would discredit the
// one claim in the report they can check for themselves.
//
// Note what this test does that grokpatrol cannot. It runs cat-file. The tool never
// can: cat-file is absent from the gitx allowlist, which is precisely what lets it
// hand over a verified pointer to a secret it is structurally unable to read.
func TestBlobIDResolvesToTheDeletedSecret(t *testing.T) {
	repo := fixtureRepo(t)
	st := runDetector(t, repo, true)

	h := hitFor(st, ".env.production")
	if h == nil {
		t.Fatal("the deleted secret was not found at all")
	}
	if !h.DeletedFromCheckout {
		t.Fatal("the fixture's deleted secret is not marked deleted")
	}
	if h.Blob == "" {
		t.Fatal("no blob id was recorded: the user has no way to verify a file they cannot see in their checkout")
	}

	out, err := exec.Command("git", "-C", repo, "cat-file", "-p", h.Blob).CombinedOutput()
	if err != nil {
		t.Fatalf("the blob id grokpatrol reported does not resolve in the repo it came from: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "hunter2") {
		t.Errorf("blob %s resolved to something other than the deleted secret:\n%s", h.Blob, out)
	}
}

// The size of the uploaded object set. "Your history went out" is an abstraction;
// a count is a fact, and it is the denominator the secret count is a numerator of.
func TestHistoryObjectCountIsReported(t *testing.T) {
	st := runDetector(t, fixtureRepo(t), true)
	if st.HistoryObjects == 0 {
		t.Error("no object count: the report cannot say how much went out with the archive")
	}
	if st.HistoryObjects < len(st.SecretFiles) {
		t.Errorf("object count %d is smaller than the %d secrets found inside it",
			st.HistoryObjects, len(st.SecretFiles))
	}
}

// A working-tree-only hit has no blob id, and must not be given one. The report
// invites the user to cat-file every id it prints; a fabricated one breaks that.
func TestWorkingTreeOnlyHitHasNoFabricatedBlob(t *testing.T) {
	st := runDetector(t, fixtureRepo(t), false) // no git: working tree only
	for _, h := range st.SecretFiles {
		if h.Blob != "" {
			t.Errorf("%s got blob %q from a scan that never read git's object database", h.Path, h.Blob)
		}
	}
}

// The headline capability: find the secrets that are invisible in the checkout.
func TestFindsSecretsDeletedFromCheckoutButAliveInHistory(t *testing.T) {
	repo := fixtureRepo(t)
	st := runDetector(t, repo, true)

	if !st.SecretsScanned {
		t.Fatalf("history was not scanned: %s", st.SecretsNote)
	}

	for _, p := range []string{".env.production", "certs/prod.pem"} {
		h := hitFor(st, p)
		if h == nil {
			t.Fatalf("%s was NOT found -- it is deleted from the checkout but still in the uploaded object set, "+
				"which is exactly the case this tool exists to catch", p)
		}
		if !h.InHistory || h.InHEAD || !h.DeletedFromCheckout {
			t.Errorf("%s: got InHistory=%v InHEAD=%v DeletedFromCheckout=%v; want true/false/true",
				p, h.InHistory, h.InHEAD, h.DeletedFromCheckout)
		}
	}

	// Still in HEAD: reported, but not flagged as the invisible kind.
	if h := hitFor(st, "terraform.tfvars"); h == nil || !h.InHEAD || h.DeletedFromCheckout {
		t.Errorf("terraform.tfvars: want InHEAD without DeletedFromCheckout, got %+v", h)
	}

	// Noise control: a template is not a credential, and a false "rotate this" costs
	// the reader trust in the real entries.
	if h := hitFor(st, ".env.example"); h != nil {
		t.Error(".env.example was reported; templates must not appear in a rotation checklist")
	}
	if h := hitFor(st, "README.md"); h != nil {
		t.Error("README.md was reported as a secret")
	}
}

// Deleted-from-checkout hits sort first: they are the ones the user cannot find
// on their own.
func TestDeletedSecretsSortFirst(t *testing.T) {
	repo := fixtureRepo(t)
	st := runDetector(t, repo, true)
	if len(st.SecretFiles) < 2 {
		t.Fatal("expected several hits")
	}
	if !st.SecretFiles[0].DeletedFromCheckout {
		t.Errorf("first reported secret is %+v; deleted-from-checkout entries must lead", st.SecretFiles[0])
	}
}

// Without git we can only see the working tree -- and we must SAY so rather than
// report an empty, reassuring result.
func TestWithoutGitDegradesHonestly(t *testing.T) {
	repo := fixtureRepo(t)
	st := runDetector(t, repo, false)

	if st.SecretsScanned {
		t.Error("SecretsScanned must be false when history was not examined")
	}
	if st.SecretsNote == "" {
		t.Error("no note explaining why the scan was incomplete")
	}
	if h := hitFor(st, ".env.production"); h != nil {
		t.Error("the deleted secret cannot be visible without reading git history")
	}
	if h := hitFor(st, "terraform.tfvars"); h == nil {
		t.Error("working-tree scan missed a secret that is right there on disk")
	}
}

// The read-only proof. A forensic tool that modifies the evidence is not a
// forensic tool -- so snapshot .git before and after, and demand byte-for-byte
// equality.
func TestRepositoryIsNeverModified(t *testing.T) {
	repo := fixtureRepo(t)
	before := snapshot(t, filepath.Join(repo, ".git"))

	runDetector(t, repo, true)

	after := snapshot(t, filepath.Join(repo, ".git"))
	if before != after {
		t.Error("the .git directory changed during the scan; grokpatrol must never touch the evidence")
	}
}

// snapshot hashes the recursive path/size/mtime listing of a tree.
func snapshot(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	var paths []string
	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, ierr := e.Info()
		if ierr != nil {
			return nil
		}
		paths = append(paths, fmt.Sprintf("%s|%d|%d", p, info.Size(), info.ModTime().UnixNano()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	for _, p := range paths {
		fmt.Fprintln(h, p)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// The template filter must match whole WORDS, not substrings.
//
// A substring filter is a false-negative machine, and a false negative is the
// worst failure this tool has: strings.Contains(".env.latest", "test") is TRUE --
// "la-TEST" -- so a naive version silently drops a live .env.latest from the
// rotation checklist. No error, no warning, just a missing row that the reader has
// no way to notice. Over-reporting a template costs five seconds; under-reporting
// a credential costs the credential.
func TestTemplateFilterDoesNotSwallowRealSecrets(t *testing.T) {
	mustReport := []string{
		".env.latest",     // contains "test"
		"contest.env",     // contains "test"
		"resample.pem",    // contains "sample"
		"attestation.key", // contains "test"
		"latest-secrets.yaml",
		"protest/prod.pem",
	}
	for _, p := range mustReport {
		if Classify(p) == "" {
			t.Errorf("Classify(%q) = \"\" -- a real secret was silently dropped from the rotation checklist "+
				"because its name happens to contain a template word as a substring", p)
		}
	}

	// Only the FILENAME decides. A directory called fixtures/ or test/ is not enough
	// to suppress a hit: a real prod.pem does sometimes sit in an oddly-named folder,
	// and dropping it to keep the report tidy would be the same false-negative trade
	// this test exists to prevent. Over-report; let the human dismiss it.
	mustSkip := []string{
		".env.example", ".env.sample", ".env.template", ".env.test",
		"config/service-account-example.json", "test.env",
	}
	for _, p := range mustSkip {
		if Classify(p) != "" {
			t.Errorf("Classify(%q) = %q -- templates must not appear in a rotation checklist", p, Classify(p))
		}
	}
}

// A directory whose NAME is secret-shaped must never be reported as a secret file.
//
// `git rev-list --objects HEAD` emits tree (directory) objects with their paths, so a
// folder called secrets/ lands in the history set; `git ls-tree -r` lists files only,
// so it is never in the checkout set. Without the tree filter the directory survives
// the subtraction and is reported as a SevCritical "deleted from the checkout" secret,
// with a blob id that resolves to a directory listing -- a fabricated finding that
// forces EXPOSED on any repo that merely has a secrets/ folder. grokpatrol would flag
// its own source tree (internal/detect/secrets) this way.
func TestDirectoryNamedLikeASecretIsNotFlagged(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	)
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir, cmd.Env = dir, env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	run("init", "-q", "--initial-branch=main")
	// A secret-named DIRECTORY holding only non-secret source, plus a genuine secret
	// FILE inside it that later gets deleted -- so the fix must drop the directory while
	// still surfacing the file.
	write("secrets/loader.go", "package secrets\n")
	write("secrets/prod.env", "DATABASE_URL=postgres://u:hunter2@prod/db\n")
	run("add", "-A")
	run("commit", "-q", "-m", "initial")
	run("rm", "-q", "secrets/prod.env")
	run("commit", "-q", "-m", "delete the env, keep it in history")

	st := runDetector(t, dir, true)

	if h := hitFor(st, "secrets"); h != nil {
		t.Errorf("the DIRECTORY %q was reported as a secret (%s, deleted=%v) -- a tree object "+
			"leaked through the history/checkout subtraction", "secrets", h.Class, h.DeletedFromCheckout)
	}
	// The real deleted secret inside it must still be found: the fix removes directories,
	// not the files under them.
	if h := hitFor(st, "secrets/prod.env"); h == nil || !h.DeletedFromCheckout {
		t.Errorf("the genuine deleted secret secrets/prod.env was lost by the tree filter: %+v", h)
	}
}

func TestClassify(t *testing.T) {
	cases := map[string]string{
		".env":                        ClassDotenv,
		".env.production":             ClassDotenv,
		"config/prod.env":             ClassDotenv,
		".env.latest":                 ClassDotenv, // "la-TEST" must not fool the template filter
		".env.example":                "",
		".env.template":               "",
		"certs/prod.pem":              ClassPrivateKey,
		"certs/prod.pub":              "",
		".ssh/id_ed25519":             ClassPrivateKey,
		"keystore.p12":                ClassKeystore,
		"config/service-account.json": ClassCloudCred,
		"credentials.json":            ClassCloudCred,
		".npmrc":                      ClassRegistry,
		"terraform.tfvars":            ClassIaC,
		"infra/terraform.tfstate":     ClassIaC,
		"kubeconfig":                  ClassKube,
		"secrets.yaml":                ClassGeneric,
		"internal/secrets/secrets.go": "", // source code, not a credential
		"README.md":                   "",
		"src/main.go":                 "",
	}
	for in, want := range cases {
		if got := Classify(in); got != want {
			t.Errorf("Classify(%q) = %q, want %q", in, got, want)
		}
	}
}
