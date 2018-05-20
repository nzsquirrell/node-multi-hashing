#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "yescrypt/yescrypt.h"
    #include "yescrypt/sha256_Y.h"
    #include "neoscrypt.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "s3.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "x14.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
    #include "fresh.h"
    #include "dcrypt.h"
    #include "jh.h"
    #include "x5.h"
    #include "c11.h"
    #include "whirlpoolx.h"
    #include "fresh.h"
    #include "zr5.h"
    #include "Lyra2RE.h"
    #include "argon2/argon2.h"
    #include "Lyra2Z.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;

Handle<Value> except(const char* msg) {
    return ThrowException(Exception::Error(String::New(msg)));
}

Handle<Value> quark(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x11(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x5(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> scrypt(const Arguments& args) {
   HandleScope scope;

   if (args.Length() < 3)
       return except("You must provide buffer to hash, N value, and R value");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   Local<Number> numn = args[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = args[2]->ToNumber();
   unsigned int rValue = numr->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> neoscrypt_hash(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2)
        return except("You must provide two arguments.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    neoscrypt(input, output, 0);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> scryptn(const Arguments& args) {
   HandleScope scope;

   if (args.Length() < 2)
       return except("You must provide buffer to hash and N factor.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   Local<Number> num = args[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> scryptjane(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 5)
        return except("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("First should be a buffer object.");

    Local<Number> num = args[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = args[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = args[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = args[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> yescrypt(const Arguments& args) {
   HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   char * input = Buffer::Data(target);
   char output[32];

   yescrypt_hash(input, output);

   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> argon2d(const Arguments& args) {
   HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

   Local<Object> target = args[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return except("Argument should be a buffer object.");

   char * input = Buffer::Data(target);
   uint32_t input_len = Buffer::Length(target);
   char output[32];
   uint32_t output_len = 32;
   uint32_t t_cost = 1; // 1 iteration
   uint32_t m_cost = 4096; // use 4MB
   uint32_t parallelism = 1; // 1 thread, 2 lanes

   argon2d_hash_raw(t_cost, m_cost, parallelism, input, input_len, input, input_len, output, output_len);

   Buffer* buff = Buffer::New(output, 32);
   return scope.Close(buff->handle_);
}

Handle<Value> keccak(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> bcrypt(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> skein(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    skein_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> groestl(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> groestlmyriad(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> blake(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> dcrypt(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    dcrypt_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> fugue(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> qubit(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> s3(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    s3_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> hefty1(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}


Handle<Value> shavite3(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> cryptonight(const Arguments& args) {
    HandleScope scope;

    bool fast = false;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    if (args.Length() >= 2) {
        if(!args[1]->IsBoolean())
            return except("Argument 2 should be a boolean");
        fast = args[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x13(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x14(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x14_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> boolberry(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2)
        return except("You must provide two arguments.");

    Local<Object> target = args[0]->ToObject();
    Local<Object> target_spad = args[1]->ToObject();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return except("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return except("Argument 2 should be a buffer object.");

    if(args.Length() >= 3)
        if(args[2]->IsUint32())
            height = args[2]->ToUint32()->Uint32Value();
        else
            return except("Argument 3 should be an unsigned integer.");

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> nist5(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> sha1(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> x15(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> fresh(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> whirlpoolx(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    whirlpoolx_hash(input, output, input_len);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> lyra2re(const Arguments& args) {
   HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2re_hash(input, output);

   Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> lyra2re2(const Arguments& args){
 HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2re2_hash(input, output);

   Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> lyra2zoin(const Arguments& args){
 HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    lyra2z_hasha(input, output);

   Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

Handle<Value> zr5(const Arguments& args) {
    HandleScope scope;

	//printf("ZR5 DEBUG MARKER:\n");
    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    zr5_hash((uint8_t *)input, (uint8_t *)output, dSize);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}



Handle<Value> c11(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1)
        return except("You must provide one argument.");

    Local<Object> target = args[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return except("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    c11_hash(input, output);

    Buffer* buff = Buffer::New(output, 32);
    return scope.Close(buff->handle_);
}

void init(Handle<Object> exports) {
    exports->Set(String::NewSymbol("quark"), FunctionTemplate::New(quark)->GetFunction());
    exports->Set(String::NewSymbol("x11"), FunctionTemplate::New(x11)->GetFunction());
    exports->Set(String::NewSymbol("scrypt"), FunctionTemplate::New(scrypt)->GetFunction());
    exports->Set(String::NewSymbol("scryptn"), FunctionTemplate::New(scryptn)->GetFunction());
    exports->Set(String::NewSymbol("scryptjane"), FunctionTemplate::New(scryptjane)->GetFunction());
    exports->Set(String::NewSymbol("keccak"), FunctionTemplate::New(keccak)->GetFunction());
    exports->Set(String::NewSymbol("bcrypt"), FunctionTemplate::New(bcrypt)->GetFunction());
    exports->Set(String::NewSymbol("skein"), FunctionTemplate::New(skein)->GetFunction());
    exports->Set(String::NewSymbol("groestl"), FunctionTemplate::New(groestl)->GetFunction());
    exports->Set(String::NewSymbol("groestlmyriad"), FunctionTemplate::New(groestlmyriad)->GetFunction());
    exports->Set(String::NewSymbol("blake"), FunctionTemplate::New(blake)->GetFunction());
    exports->Set(String::NewSymbol("fugue"), FunctionTemplate::New(fugue)->GetFunction());
    exports->Set(String::NewSymbol("qubit"), FunctionTemplate::New(qubit)->GetFunction());
    exports->Set(String::NewSymbol("hefty1"), FunctionTemplate::New(hefty1)->GetFunction());
    exports->Set(String::NewSymbol("shavite3"), FunctionTemplate::New(shavite3)->GetFunction());
    exports->Set(String::NewSymbol("cryptonight"), FunctionTemplate::New(cryptonight)->GetFunction());
    exports->Set(String::NewSymbol("x13"), FunctionTemplate::New(x13)->GetFunction());
    exports->Set(String::NewSymbol("x14"), FunctionTemplate::New(x14)->GetFunction());
    exports->Set(String::NewSymbol("boolberry"), FunctionTemplate::New(boolberry)->GetFunction());
    exports->Set(String::NewSymbol("nist5"), FunctionTemplate::New(nist5)->GetFunction());
    exports->Set(String::NewSymbol("sha1"), FunctionTemplate::New(sha1)->GetFunction());
    exports->Set(String::NewSymbol("x15"), FunctionTemplate::New(x15)->GetFunction());
    exports->Set(String::NewSymbol("whirlpoolx"), FunctionTemplate::New(whirlpoolx)->GetFunction());
    exports->Set(String::NewSymbol("fresh"), FunctionTemplate::New(fresh)->GetFunction());
    exports->Set(String::NewSymbol("zr5"), FunctionTemplate::New(zr5)->GetFunction());
    exports->Set(String::NewSymbol("ziftr"), FunctionTemplate::New(zr5)->GetFunction());
    exports->Set(String::NewSymbol("neoscrypt"), FunctionTemplate::New(neoscrypt_hash)->GetFunction());
    exports->Set(String::NewSymbol("yescrypt"), FunctionTemplate::New(yescrypt)->GetFunction());
    exports->Set(String::NewSymbol("lyra2re"), FunctionTemplate::New(lyra2re)->GetFunction());
    exports->Set(String::NewSymbol("lyra2re2"), FunctionTemplate::New(lyra2re2)->GetFunction());
    exports->Set(String::NewSymbol("c11"), FunctionTemplate::New(c11)->GetFunction());
	exports->Set(String::NewSymbol("s3"), FunctionTemplate::New(s3)->GetFunction());
	exports->Set(String::NewSymbol("dcrypt"), FunctionTemplate::New(dcrypt)->GetFunction());
    exports->Set(String::NewSymbol("c11"), FunctionTemplate::New(c11)->GetFunction());
    exports->Set(String::NewSymbol("argon2d"), FunctionTemplate::New(argon2d)->GetFunction());
}

NODE_MODULE(multihashing, init)
