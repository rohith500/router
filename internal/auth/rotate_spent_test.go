package auth_test

// TestRotateAPIKey_preservesAccumulatedSpend documents the spend-reset bug:
// RotateAPIKey creates a replacement key via IssueAPIKeyWithCap, which does not
// forward spent_usd_micros. The new key always starts with SpentUsdMicros == 0,
// silently erasing all accumulated spend. Combined with the cap now correctly
// carrying forward (#565), a key near its cap can be rotated repeatedly to
// indefinitely reset its spend counter, bypassing the cap entirely.
//
// Fix: propagate SpentUsdMicros through CreateAPIKeyParams so RotateAPIKey
// carries the old key's accumulated spend onto the new one.

import (
	"context"
	"testing"

	"workweave/router/internal/auth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rotateSpentKeyRepo mirrors rotateCapKeyRepo but also forwards SpentUsdMicros
// from CreateAPIKeyParams onto the returned APIKey, so the assertion can verify
// whether RotateAPIKey actually passed the spent value through.
type rotateSpentKeyRepo struct {
	keys []*auth.APIKey
}

func (r *rotateSpentKeyRepo) Create(_ context.Context, p auth.CreateAPIKeyParams) (*auth.APIKey, error) {
	key := &auth.APIKey{
		ID:                auth.GenerateID("kid"),
		InstallationID:    p.InstallationID,
		ExternalID:        p.ExternalID,
		Name:              p.Name,
		KeyPrefix:         p.KeyPrefix,
		KeyHash:           p.KeyHash,
		KeySuffix:         p.KeySuffix,
		CreatedBy:         p.CreatedBy,
		SpendCapUsdMicros: p.SpendCapUsdMicros,
		SpentUsdMicros:    p.SpentUsdMicros,
	}
	r.keys = append(r.keys, key)
	return key, nil
}

func (r *rotateSpentKeyRepo) GetActiveByHashWithInstallation(_ context.Context, _ string) (*auth.APIKey, *auth.Installation, error) {
	return nil, nil, nil
}

func (r *rotateSpentKeyRepo) ListForInstallation(_ context.Context, installationID string) ([]*auth.APIKey, error) {
	var out []*auth.APIKey
	for _, k := range r.keys {
		if k.InstallationID == installationID && k.DeletedAt == nil {
			out = append(out, k)
		}
	}
	return out, nil
}

func (r *rotateSpentKeyRepo) MarkUsed(_ context.Context, _ string) error { return nil }

func (r *rotateSpentKeyRepo) SoftDelete(_ context.Context, installationID, id string) error {
	for _, k := range r.keys {
		if k.InstallationID == installationID && k.ID == id {
			now := frozenClock()()
			k.DeletedAt = &now
		}
	}
	return nil
}

func TestRotateAPIKey_preservesAccumulatedSpend(t *testing.T) {
	const installationID = "00000000-0000-0000-0000-000000000001"
	cap := int64(50_000_000) // $50.00 in micros

	repo := &rotateSpentKeyRepo{}
	svc := auth.NewService(
		&fakeInstallationRepository{},
		repo,
		nil, // externalKeys — unused
		nil, // users — unused
		auth.NoOpAPIKeyCache{},
		nil, // userCache — unused
		frozenClock(),
	)

	// Seed a key that is near its cap: $49 of $50 spent.
	originalKeyID := auth.GenerateID("kid")
	originalName := "near-cap-key"
	original := &auth.APIKey{
		ID:                originalKeyID,
		InstallationID:    installationID,
		ExternalID:        auth.GenerateID("ekid"),
		Name:              &originalName,
		KeyHash:           "hash-of-original",
		KeyPrefix:         "rk_or",
		KeySuffix:         "igin",
		SpendCapUsdMicros: &cap,
		SpentUsdMicros:    49_000_000, // $49.00 accumulated
	}
	repo.keys = append(repo.keys, original)

	// Rotate the near-cap key.
	newKey, _, err := svc.RotateAPIKey(context.Background(), installationID, originalKeyID, nil)
	require.NoError(t, err)

	// Regression guard: cap must still be carried forward (fix from #565).
	require.NotNil(t, newKey.SpendCapUsdMicros,
		"spend cap must be carried forward to the replacement key")
	assert.Equal(t, cap, *newKey.SpendCapUsdMicros,
		"replacement key's spend cap must equal the original key's cap")

	// Bug: spent_usd_micros resets to 0 on rotation. The replacement key must
	// carry the old key's accumulated spend so the cap remains enforced.
	//
	// This assertion FAILS with the current implementation because
	// IssueAPIKeyWithCap does not forward SpentUsdMicros through
	// CreateAPIKeyParams, so the new key always starts at 0.
	assert.Equal(t, int64(49_000_000), newKey.SpentUsdMicros,
		"accumulated spend must be carried forward; got 0 — cap bypass possible via rotation")
}
