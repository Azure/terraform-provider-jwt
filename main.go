package main

import (
	"github.com/Azure/terraform-provider-jwt/jwt"
	"github.com/hashicorp/terraform/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: jwt.Provider})
}
