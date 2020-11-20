package jwt

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

// Provider returns the jwt prvoider to serve as a plugin
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"jwt_hashed_token": resourceHashedToken(),
			"jwt_signed_token": resourceSignedToken(),
		},
		DataSourcesMap: map[string]*schema.Resource{},
	}
}
