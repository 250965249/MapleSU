package android.util
object Base64 {
 const val NO_WRAP=2
 fun encodeToString(bytes:ByteArray,offset:Int,size:Int,flags:Int):String = java.util.Base64.getEncoder().encodeToString(bytes.copyOfRange(offset,offset+size))
 fun decode(value:String,flags:Int):ByteArray=java.util.Base64.getDecoder().decode(value)
}
object Log { fun w(tag:String,message:String)=0; fun w(tag:String,message:String,error:Throwable)=0; fun e(tag:String,message:String,error:Throwable)=0 }
