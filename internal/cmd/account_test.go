package cmd

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/steipete/gogcli/internal/config"
	"github.com/steipete/gogcli/internal/secrets"
)

type fakeSecretsStore struct {
	defaultAccount string
	tokens         []secrets.Token
	errDefault     error
	errListTokens  error
}

func (s *fakeSecretsStore) Keys() ([]string, error) { return nil, errors.New("not implemented") }
func (s *fakeSecretsStore) SetToken(string, string, secrets.Token) error {
	return errors.New("not implemented")
}

func (s *fakeSecretsStore) GetToken(string, string) (secrets.Token, error) {
	return secrets.Token{}, errors.New("not implemented")
}
func (s *fakeSecretsStore) DeleteToken(string, string) error { return errors.New("not implemented") }
func (s *fakeSecretsStore) SetDefaultAccount(string, string) error {
	return errors.New("not implemented")
}

func (s *fakeSecretsStore) GetDefaultAccount(string) (string, error) {
	return s.defaultAccount, s.errDefault
}
func (s *fakeSecretsStore) ListTokens() ([]secrets.Token, error) { return s.tokens, s.errListTokens }

func TestRequireAccount_PrefersFlag(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	flags := &RootFlags{Account: "flag@example.com"}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "flag@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_UsesEnv(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "env@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_ResolvesAliasFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	if err := config.WriteConfig(config.File{
		AccountAliases: map[string]string{"work": "alias@example.com"},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	flags := &RootFlags{Account: "work"}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "alias@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_ResolvesAliasEnv(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "xdg-config"))
	if err := config.WriteConfig(config.File{
		AccountAliases: map[string]string{"work": "alias@example.com"},
	}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Setenv("GOG_ACCOUNT", "work")
	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "alias@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_AutoUsesDefault(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{Account: "auto"}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{defaultAccount: "default@example.com"}, nil
	}

	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "default@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_Missing(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}
	_, err := requireAccount(flags)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRequireAccount_UsesKeyringDefaultAccount(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{defaultAccount: "default@example.com"}, nil
	}

	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "default@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_UsesSingleStoredToken(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{
			tokens: []secrets.Token{{Email: "one@example.com", Client: config.DefaultClientName}},
		}, nil
	}

	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "one@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_MissingWhenMultipleTokensAndNoDefault(t *testing.T) {
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		return &fakeSecretsStore{
			tokens: []secrets.Token{{Email: "a@example.com", Client: config.DefaultClientName}, {Email: "b@example.com", Client: config.DefaultClientName}},
		}, nil
	}

	_, err := requireAccount(flags)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRequireAccount_AccessTokenWithAccount(t *testing.T) {
	t.Setenv("GOG_ACCESS_TOKEN", "ya29.test-token")
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{Account: "flag@example.com"}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "flag@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_AccessTokenWithEnvAccount(t *testing.T) {
	t.Setenv("GOG_ACCESS_TOKEN", "ya29.test-token")
	t.Setenv("GOG_ACCOUNT", "env@example.com")
	flags := &RootFlags{}
	got, err := requireAccount(flags)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "env@example.com" {
		t.Fatalf("got %q", got)
	}
}

func TestRequireAccount_AccessTokenWithoutAccount(t *testing.T) {
	t.Setenv("GOG_ACCESS_TOKEN", "ya29.test-token")
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	// Ensure keyring is never consulted.
	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		t.Fatalf("secrets store should not be opened in access-token mode")
		return nil, nil
	}

	_, err := requireAccount(flags)
	if err == nil {
		t.Fatalf("expected error when GOG_ACCESS_TOKEN set without account")
	}
	if !strings.Contains(err.Error(), "GOG_ACCESS_TOKEN") {
		t.Fatalf("error should mention GOG_ACCESS_TOKEN, got: %v", err)
	}
}

func TestRequireAccount_AccessTokenSkipsKeyringDefault(t *testing.T) {
	t.Setenv("GOG_ACCESS_TOKEN", "ya29.test-token")
	t.Setenv("GOG_ACCOUNT", "")
	flags := &RootFlags{}

	// A keyring default exists, but should NOT be used in access-token mode
	// because it may refer to a different account than the token was minted for.
	prev := openSecretsStoreForAccount
	t.Cleanup(func() { openSecretsStoreForAccount = prev })
	openSecretsStoreForAccount = func() (secrets.Store, error) {
		t.Fatalf("secrets store should not be opened in access-token mode")
		return nil, nil
	}

	_, err := requireAccount(flags)
	if err == nil {
		t.Fatalf("expected error, keyring default should not be used")
	}
}
