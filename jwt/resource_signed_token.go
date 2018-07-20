package jwt

import (
	"encoding/json"
	"encoding/pem"
	"fmt"

	jwtgen "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceSignedToken() *schema.Resource {
	return &schema.Resource{
		Create: createSignedJWT,
		Delete: deleteSignedJWT,
		Read:   readSignedJWT,

		Schema: map[string]*schema.Schema{
			"algorithm": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Signing algorithm to use",
				ValidateFunc: validateSigningAlgorithm,
				ForceNew:     true,
			},
			"key": &schema.Schema{
				Type:         schema.TypeString,
				Required:     true,
				Description:  "PEM-formated key to sign the JWT with",
				ValidateFunc: validateSigningKey,
				ForceNew:     true,
				Sensitive:    true,
			},
			"claims": &schema.Schema{
				Type:        schema.TypeMap,
				Required:    true,
				Description: "The token's claims",
				ForceNew:    true,
			},
			"token": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func createSignedJWT(d *schema.ResourceData, meta interface{}) (err error) {
	alg := d.Get("algorithm").(string)
	signer := jwtgen.GetSigningMethod(alg)
	token := jwtgen.NewWithClaims(signer, jwtgen.MapClaims(d.Get("claims").(map[string]interface{})))

	var key interface{}
	sKey := d.Get("key").(string)

	if _, ok := signer.(*jwtgen.SigningMethodECDSA); ok {
		key, err = jwtgen.ParseECPrivateKeyFromPEM([]byte(sKey))
	} else if _, ok := signer.(*jwtgen.SigningMethodRSA); ok {
		key, err = jwtgen.ParseRSAPrivateKeyFromPEM([]byte(sKey))
	} else {
		err = fmt.Errorf("This provider doesn't know what key type goes with %s", alg)
	}
	if err != nil {
		return
	}

	signedToken, err := token.SignedString(key)
	if err != nil {
		return err
	}
	compactClaims, _ := json.Marshal(token.Claims)
	d.SetId(string(compactClaims))
	d.Set("token", signedToken)
	return
}

func deleteSignedJWT(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func readSignedJWT(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func validateSigningAlgorithm(iAlg interface{}, k string) (warnings []string, errs []error) {
	alg, ok := iAlg.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string", k))
		return
	}
	method := jwtgen.GetSigningMethod(alg)
	if method == nil {
		errs = append(errs, fmt.Errorf("%s is not a supported signing algorithim. Options are RS256, RS384, RS512, ES256, ES384, ES512", alg))
		return
	}
	if _, isHMAC := method.(*jwtgen.SigningMethodHMAC); isHMAC {
		errs = append(errs, fmt.Errorf("For HMAC signing, please use the jwt_hashed_token resource"))
	}
	return
}

func validateSigningKey(iKey interface{}, k string) (warnings []string, errs []error) {
	key, ok := iKey.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string", k))
		return
	}
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		errs = append(errs, fmt.Errorf("%s must be PEM encoded", k))
	}
	// ideally we would validate that key was the right type (RSA vs ECDSA, but I don't think
	// validation functions can access multiple keys, so we'll just have to delay that til create time
	return
}
