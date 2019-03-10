package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"fmt"
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
	DSPK userlib.DSSignKey		//Digital Signature Private Key
	PKEPK userlib.PKEDecKey		//Public Key Encryption Private Key
	DSSignature []byte			//Digital Signature of user
	FAT map[string]uuid.UUID 	//create File Allocation Table
	Password string 			//User Password

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
	    return nil, DSerror
	}

	//generate assym encrypt
	PKEEncKey, PKEDecKey, PKEerror := userlib.PKEKeyGen()
	if PKEerror != nil {
	    return nil, PKEerror
	}

	//store private key into userdata
	userdataptr.Username =  username
	userdataptr.DSPK = DSSignKey
	userdataptr.PKEPK= PKEDecKey 
	userdataptr.FAT = make(map[string]uuid.UUID)
	userdataptr.Password = password

	// Sign, Encrypt & Store User Data onto DataStore
	SignEncStoreError := SignEncStoreUser(userdataptr)
	if SignEncStoreError != nil {
		return nil, SignEncStoreError
	}

	//post DS on keystore
	DSStoreerror := userlib.KeystoreSet(username+"DS",DSVerifyKey)
	if DSStoreerror != nil {
		return nil, DSStoreerror
	}

	//post PKE on keystore
	PKEStoreError := userlib.KeystoreSet(username+"PKE",PKEEncKey)
	if PKEStoreError != nil {
		return nil, PKEStoreError
	}
	return &userdata, nil
}

func SignEncStoreUser (userdataptr *User) error {
	//use password to create key for datastore
	datastoreKey := userlib.Argon2Key([]byte(userdataptr.Password),[]byte(userdataptr.Username),16)

	//create byte for userdata
	userdataJSON, JSONerror := json.Marshal(userdataptr)
	if JSONerror != nil {
	    return JSONerror
	}

	//create and store Signature for userdata
	DSSignature, DSSignError := userlib.DSSign(userdataptr.DSPK,userdataJSON)
	if DSSignError != nil {
	    return DSSignError
	}
 	
 	userlib.DebugMsg(string(DSSignature))

 	//get encryption key  
 	encryptedKey, encryptError := userlib.HMACEval(datastoreKey[:16], []byte(userdataptr.Password))
	encryptedKey = encryptedKey[:16]
	if encryptError != nil {
	    return encryptError
	}

	//create encrypted userdata
	encryptedUserdata := userlib.SymEnc(encryptedKey, userlib.RandomBytes(16),
		append(userdataJSON,DSSignature...))
	if encryptedUserdata = nil {
		return errors.New("encrypt userdata fail")
	}

	//store encrypted User on Datastore
	userlib.DatastoreSet(bytesToUUID([]byte(datastoreKey)[:16]),
		encryptedUserdata)

	return nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	// var userdata User
	// userdataptr = &userdata

	//create key from password
	datastoreKey := userlib.Argon2Key([]byte(password),[]byte(username),16)

	//create decryption key from datastoreKey
 	decryptionKey, decryptError := userlib.HMACEval(datastoreKey[:16], []byte(password))
	decryptionKey = decryptionKey[:16]
	if decryptError != nil {
		return nil, decryptError
	}

	//get encrypted user structure from datastore
	encryptedUserdata, ok := userlib.DatastoreGet(bytesToUUID([]byte(datastoreKey)[:16]))
	if !ok{
		return nil, errors.New("get encrypted data fail")
	}
	//decrypt the userdata
	decryptedUserdata := userlib.SymDec(decryptionKey,encryptedUserdata)

	//get userdata and signature
	userdataJSON := decryptedUserdata[:len(decryptedUserdata)-256]
	DSSignature := decryptedUserdata[len(decryptedUserdata)-256:]

	//Get DS Verify Key Signature
	DSVerifyKey, ok := userlib.KeystoreGet(username+"DS")
	if !ok {
	    return nil, errors.New("get DS Verify Key fail")
	}

	//Verify Data Integrity and Authenticity
	VerifyError := userlib.DSVerify(DSVerifyKey,userdataJSON,DSSignature)
	if VerifyError != nil {
	    return nil, VerifyError
	}

	//getting userdata from JSON
	var userdata User
	json.Unmarshal(userdataJSON, &userdata)

	return &userdata, VerifyError
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	var fileUUID uuid.UUID

	//check if file already exists
	if val,ok := userdata.FAT[filename]; ok{
		//if exists, get old UUID
		fileUUID = val
		userlib.DebugMsg("File already exists in user's FAT.")
	} else {
		//else generate random bits to create UUID
		fileUUID = uuid.New()

		//store UUID in FAT
		userdata.FAT[filename] = fileUUID
		userlib.DebugMsg("Inserting new file entry into user's FAT")

		// Update User Data onto DataStore
		SignEncStoreError := SignEncStoreUser(userdata)
		if SignEncStoreError != nil {
		    return nil, SignEncStoreError
		}
	}

<<<<<<< HEAD
	//Sign the file
	DSSignature, DSSignError := userlib.DSSign(userdata.DSPK, data)
	if DSSignError != nil {
		return nil, DSSignError
	}

=======
	//get public key
	PKEEncKey, ok := userlib.KeystoreGet(userdata.Username+"PKE")
	if !ok {
		userlib.DebugMsg("keystore get")
	}

	//encrypt the file
	encryptedFile, encryptError := userlib.PKEEnc(PKEEncKey, append(data,DSSignature...))
	if encryptError != nil {
		return nil, encryptError
	}

	//store encrypted file in Datastore
	userlib.DatastoreSet(fileUUID, encryptedFile)
  	
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
	var fileUUID uuid.UUID

	//check if file exists
	if val,ok := userdata.FAT[filename]; ok{
		//if exists, get old UUID
		fileUUID = val
		userlib.DebugMsg("File already exists in user's FAT.")
	} else {
		return nil, errors.New("File does not exist")
	}

	// Get File from Datastore
	EncryptedFile, DSGetOk := userlib.DatastoreGet(fileUUID)
	if !DSGetOk {
		return nil, errors.New("File does not exist")
	}

	// Decrypt File from Datastore
	DecryptedFile, DecryptError := userlib.PKEDec(userdata.PKEPK, EncryptedFile)
	if DecryptError != nil {
		return nil, DecryptError
	}
	
	// Get DSS Signature
	FileData := DecryptedFile[:len(DecryptedFile)-256]
	DSSignature := DecryptedFile[len(DecryptedFile)-256:]

	// Get User's DSVerifyKey from Keystore
	DSVerifyKey, DSGetOk := userlib.KeystoreGet(userdata.Username+"DS")
	if !DSGetOk {
	    return nil, errors.New("Error Obtaining User's DSVerifyKey")
	}

	// Verify File from Datastore
	VerifyError := userlib.DSVerify(DSVerifyKey, DecryptedFile, DSSignature)
	if VerifyError != nil {
	    return nil, VerifyError
	}

	// Return file if ok
	
	return FileData, nil
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
