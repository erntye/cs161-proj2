package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
        var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username string
	DSPK userlib.DSSignKey
	PKEPK userlib.PKEDecKey
	DSSignature []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//generate dig sig
	DSSignKey, DSVerifyKey, DSerror := userlib.DSKeyGen()
	if DSerror != nil {
	    userlib.DebugMsg(DSerror.Error())
	}

	//generate assym encrypt
	PKEEncKey, PKEDecKey, PKEerror := userlib.PKEKeyGen()
	if PKEerror != nil {
	    userlib.DebugMsg(PKEerror.Error())
	}

	//store private key into userdata
	userdataptr.Username =  username
	userdataptr.DSPK = DSSignKey
	userdataptr.PKEPK= PKEDecKey 

	//use password to create key for datastore
	datastoreKey := userlib.Argon2Key([]byte(password),[]byte(username),256)

	//create byte for userdata
	userdataJSON, JSONerror := json.Marshal(userdataptr)
	if JSONerror != nil {
	    userlib.DebugMsg(JSONerror.Error())
	}

	//create and store DS for userdata
	DSSignature, DSSignError := userlib.DSSign(userdataptr.DSPK,userdataJSON)
	if DSSignError != nil {
	    userlib.DebugMsg(DSSignError.Error())
	}
 	userlib.DebugMsg(string(DSSignature))

	//store User on Datastore
	userlib.DatastoreSet(bytesToUUID([]byte(datastoreKey)[:16]),
		append(userdataJSON,DSSignature...))

	//post DS on keystore
	DSStoreerror := userlib.KeystoreSet(username+"DS",DSVerifyKey)
	if DSStoreerror != nil {
	    userlib.DebugMsg(DSStoreerror.Error())
	}

	//post PKE on keystore
	PKEStoreError := userlib.KeystoreSet(username+"PKE",PKEEncKey)
	if PKEStoreError != nil {
	    userlib.DebugMsg(PKEStoreError.Error())
	}
	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// var userdata User
	// userdataptr = &userdata

	//create key from password
	datastoreKey := userlib.Argon2Key([]byte(password),[]byte(username),256)

	//get User struct from key
	userdataSignature, ok := userlib.DatastoreGet(bytesToUUID([]byte(datastoreKey)[:16]))
	userdataJSON := userdataSignature[:len(userdataSignature)-256]
	DSSignature := userdataSignature[len(userdataSignature)-256:]

	//Get DS Verify Key Signature
	DSVerifyKey, ok := userlib.KeystoreGet(username+"DS")
	if !ok {
	    userlib.DebugMsg("DSGet error")
	}

	//Verify Data Integrity and AUTHENTICITY
	VerifyError := userlib.DSVerify(DSVerifyKey,userdataJSON,DSSignature)
	if VerifyError != nil {
	    userlib.DebugMsg(VerifyError.Error())
	}

	//getting userdata from JSON
	var userdata User
	json.Unmarshal(userdataJSON, &userdata)

	// userdataptr := &userdata
	userlib.DebugMsg("DO I WORK")
	return &userdata, VerifyError
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	return
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	return
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	return
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	return
}
