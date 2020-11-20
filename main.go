package main

import (
	"github.com/camptocamp/terraform-provider-jwt/jwt"
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: jwt.Provider,
	})
}
