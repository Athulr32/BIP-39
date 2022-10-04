package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	// "math/big"
	// "crypto/pbkdf2"
	"bufio"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/pbkdf2"
	"log"
	"os"
	"strconv"
	"strings"
	// "reflect"
	// "encoding/binary"
)

type bitString string

func (b bitString) AsByteSlice() []byte {
	var out []byte
	var str string

	for i := len(b); i > 0; i -= 8 {
		if i-8 < 0 {
			str = string(b[0:i])
		} else {
			str = string(b[i-8 : i])
		}
		v, err := strconv.ParseUint(str, 2, 8)
		if err != nil {
			panic(err)
		}
		out = append([]byte{byte(v)}, out...)
	}
	return out
}

func reverse(s string) string {
    rns := []rune(s) // convert to rune
    for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
  
        // swap the letters of the string,
        // like first with last and so on.
        rns[i], rns[j] = rns[j], rns[i]
    }
  
    // return the reversed string.
    return string(rns)
}

func toBinary(num uint32) string{

	var binary string="";

	for num>0 {
	
		r:=num%2;
		num=num/2;
		temp:=strconv.Itoa(int(r))
		binary=binary+temp
	
	}

	n:=len(binary);
	for i:=n;i<32;i++{
		binary=binary+"0"
	}

	return reverse(binary);


}


func inArray(word string, arr []string) (bool, int) {

	for i, ele := range arr {

		if ele == word {
			return true, i
		}
	}

	return false, 0
}


func entropyGenerator() ([]byte, string) {

	n := 16
	entropyByte := make([]byte, n)
	_, err := rand.Read(entropyByte)
	if err != nil {
		panic(err)
	}

	entropyHex := hex.EncodeToString(entropyByte)

	return entropyByte, entropyHex
}

func byteToBit(bytes []byte) string {

	bits := make([]string, len(bytes))

	for i, ele := range bytes {

		bin := strconv.FormatInt(int64(ele), 2)

		if len(bin) < 8 {
			length := 8 - len(bin)
			for j := 0; j < length; j++ {

				bin = "0" + bin
			}

		}
		bits[i] = bin

	}

	entropy := strings.Join(bits, "")

	return entropy

}

func checkSum(entropyBit *string, entropyHex string) {

	checkSumLength := len(*entropyBit) / 32

	decoded, err := hex.DecodeString(entropyHex)

	if err != nil {
		log.Fatal(err)
	}
	hash := sha256.Sum256([]byte(decoded))

	bitHash := byteToBit(hash[:])

	*entropyBit = *entropyBit + bitHash[0:checkSumLength]



}

func words(entropy string) string {

	file, err := os.Open("./words.txt")
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	wordsBit := make([]string, len(entropy)/11)
	i := 0
	n := 0
	for i < len(entropy) {

		wordsBit[n] = entropy[i : i+11]
		i = i + 11
		n++
	}

	scanner := bufio.NewScanner(file)
	var index int64 = 0

	mnemonics := make([]string, len(wordsBit))

	for scanner.Scan() {
		data := scanner.Text()
		bin := strconv.FormatInt(index, 2)

		if len(bin) != 11 {
			length := 11 - len(bin)
			for j := 0; j < length; j++ {

				bin = "0" + bin
			}

		}

		check, pos := inArray(bin, wordsBit)

		if check {
			mnemonics[pos] = data

		}

		index++

	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	mnemonicsString := strings.Join(mnemonics, " ")
	return mnemonicsString

}

func mnemonicToSeed(mnemonic []byte) []byte {
	
	salt := []byte("mnemonic")
	seed := pbkdf2.Key(mnemonic, salt, 2048, 64, sha512.New)

	return seed

}

func hmacHashing(seed []byte) []byte {

	mac := hmac.New(sha512.New, seed)

	hmacSeed := mac.Sum(nil)

	return hmacSeed

}

func keyDerivation(hmacSeedBits string) {

	//Index number
	var index uint32 = 0;

	//Private Key
	masterKey := hmacSeedBits[0:256]

	bin := bitString(masterKey).AsByteSlice()

	//Chain code
	masterChainCode:=hmacSeedBits[256:]
	
	keyGen := secp256k1.S256()

	//Pub Key
	x, y := keyGen.ScalarBaseMult(bin)

	//Compressed public key

	compPk := secp256k1.CompressPubkey(x, y)
	compPkbit:=byteToBit(compPk)
	fmt.Printf("%x", compPk)

		combinedBit:= compPkbit+masterChainCode+toBinary(index);

		hmacHash:=hmacHashing(bitString(combinedBit).AsByteSlice())


}

func main() {

	// entropyByte, entropyHex := entropyGenerator()

	// entropyBit := byteToBit(entropyByte)


	// //Add checksum to entropyBit
	// checkSum(&entropyBit, entropyHex)

	// //Get the mnemonic phrase from entropyBits
	// mnemonics := words(entropyBit)
	// fmt.Println(mnemonics)

	// seed := mnemonicToSeed([]byte(mnemonics))


	// //Put the seed into HMAC-512 alogirthm
	// hmacSeed := hmacHashing(seed)
	// hmacSeedBits := byteToBit(hmacSeed)
	// keyDerivation(hmacSeedBits)

	fmt.Print(toBinary(3))

}
