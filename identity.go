package goauth

import "github.com/disaster37/go-auth/domain"

// Core domain types re-exported from domain for ergonomic top-level usage.
type (
	Identity             = domain.Identity
	Role                 = domain.Role
	AuthMethod           = domain.AuthMethod
	User                 = domain.User
	Group                = domain.Group
	APIToken             = domain.APIToken
	LegacyTokenValidator = domain.LegacyTokenValidator
)

// Role constants.
const (
	RoleAdmin = domain.RoleAdmin
	RoleUser  = domain.RoleUser
)

// AuthMethod constants.
const (
	AuthMethodJWT         = domain.AuthMethodJWT
	AuthMethodSession     = domain.AuthMethodSession
	AuthMethodAPIToken    = domain.AuthMethodAPIToken
	AuthMethodLegacyToken = domain.AuthMethodLegacyToken
	AuthMethodOIDC        = domain.AuthMethodOIDC
	AuthMethodInternal    = domain.AuthMethodInternal
)
