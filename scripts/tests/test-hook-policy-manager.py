"""Compile policy manager orchestration locally, with Android/Root fixture boundaries."""
import argparse
from datetime import datetime,timezone
import hashlib,json,os,subprocess,sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
import native_toolchain  # noqa: E402
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools/specgen'))
from specgen.product import cached_jar
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',required=True,type=Path);a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=True);stubs=a.out/'stubs';stubs.mkdir(exist_ok=True)
fixtures={
'modules.kt':'''package dev.maplesu.manager.modules
import android.content.Context
import java.io.File
object UltraRootKeyStore { fun read(context:Context)="" }
data class ModuleScriptOutput(val code:Int,val out:String="",val err:String="") { val isSuccess get()=code==0 }
object RootExecModuleScriptRunner {
    val calls=mutableListOf<String>()
    var resident=false
    fun runHook(context:Context,script:String):ModuleScriptOutput {
        calls+=script
        check("hook-load" !in script)
        if(script.endsWith(" hook-info")) {
            check(resident)
            return ModuleScriptOutput(0,"""{"present":true,"controlAbi":2,"buildId":"","pageSize":4096}""")
        }
        return ModuleScriptOutput(0,if(script.endsWith(" config-hook 3"))
            """{"requested":3,"effective":3,"capabilities":3}""" else
            """{"requested":1,"effective":1,"capabilities":1}""")
    }
}
object ModuleToolDeployment { fun policySource(context:Context)=File("/fake/policy") }
''',
'probe.kt':'package dev.maplesu.manager.runtime.ultra\nimport android.content.Context\nobject UltraEnvironmentProbe { fun usesUltraBackend(context:Context)=false }\nclass UltraRuntimeClient(val key:()->String) { fun modulePolicySettings(value:Int)=Receipt() }\nclass Receipt { val succeeded=true;val reason:String?=null;val sdkError="";val data:org.json.JSONObject?=null }\n',
'android.kt':'package android.content\nopen class Context { val assets=android.content.res.AssetManager();val filesDir get()=java.io.File(".").also { fileReads++ };fun getSharedPreferences(name:String,mode:Int)=Preferences();companion object { const val MODE_PRIVATE=0;var fileReads=0 } }\nclass Preferences { fun getBoolean(name:String,default:Boolean)=default;fun edit()=Editor() }\nclass Editor { fun putBoolean(name:String,value:Boolean)=this;fun commit()=true }\n',
'assets.kt':'package android.content.res\nclass AssetManager { companion object { var opens=0 };fun open(name:String):java.io.InputStream { opens++;throw java.io.FileNotFoundException(name) } }\n',
'system.kt':'package android.system\nobject Os { var chmods=0;fun uname()=Name();fun sysconf(name:Int)=4096L;fun chmod(path:String,mode:Int) { chmods++ } }\nclass Name { val release="6.12.58-vendor" }\nobject OsConstants { const val _SC_PAGESIZE=1 }\n',
'log.kt':'package android.util\nobject Log { fun w(tag:String,message:String,error:Throwable)=0 }\n'}
row=dict(asset='maplesu/policy-hook/test.ko',sha256='a'*64,bytes=128,buildId='b'*40,kernelRelease='6.12.58-vendor',pageSize=4096)
def manifest(rows,abi=2):return json.dumps(dict(schemaVersion=1,controlAbi=abi,images=rows))
valid=json.dumps(manifest([row]));invalid=[json.dumps(manifest([row|dict(asset='maplesu/policy-hook/../outside.ko')])),json.dumps(manifest([row],1)),json.dumps(manifest([row,row]))]
fixtures['test.kt']='''package dev.maplesu.manager.modules
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
class HookPolicyBackendTest {
    @Before fun reset() {
        RootExecModuleScriptRunner.calls.clear();RootExecModuleScriptRunner.resident=false
        android.content.res.AssetManager.opens=0;android.content.Context.fileReads=0;android.system.Os.chmods=0
    }
    @Test fun parsesMeasuredArtifact() { val row=HookPolicyBackend.parse('''+valid+''').single();assertEquals(4096L,row.pageSize);assertEquals("b".repeat(40),row.buildId) }
    @Test fun rejectsInvalidInventory() { for(value in listOf('''+','.join(invalid)+''')) { assertThrows(IllegalArgumentException::class.java) { HookPolicyBackend.parse(value) } } }
    @Test fun readsDoNotLoadBackend() {
        val state=UltraModulePolicyRepository.read(android.content.Context())
        assertEquals(1,state.effective);assertFalse(state.canTryUnverified)
        assertEquals(listOf("config"),commands())
    }
    private fun commands()=RootExecModuleScriptRunner.calls.map { it.substringAfterLast("' ") }
    private fun noSidecarAccess() {
        assertEquals(0,android.content.res.AssetManager.opens)
        assertEquals(0,android.content.Context.fileReads);assertEquals(0,android.system.Os.chmods)
    }
    @Test fun residentEnsureSkipsInventoryAndStaging() {
        RootExecModuleScriptRunner.resident=true
        HookPolicyBackend.ensure(android.content.Context())
        assertEquals(listOf("hook-info"),commands())
        noSidecarAccess()
    }
    @Test fun saveUsesResidentControlWithoutSidecar() {
        RootExecModuleScriptRunner.resident=true
        val state=UltraModulePolicyRepository.save(android.content.Context(),3)
        assertEquals(3,state.requested);assertEquals(3,state.effective)
        assertEquals(listOf("hook-info","config-hook 3"),commands())
        noSidecarAccess()
    }
}
'''
for name,text in fixtures.items():(stubs/name).write_text(text)
sources=[ROOT/'manager/src/main/java/dev/maplesu/manager/modules'/n for n in ['HookPolicyBackend.kt','UltraModulePolicyRepository.kt','UltraModulePolicyState.kt']]
viewmodel=ROOT/'manager/src/main/java/com/maplesu/core/ui/viewmodel/SettingsViewModel.kt'
refresh=viewmodel.read_text(encoding='utf-8').split('private fun refreshUltraModulePolicy()',1)[1].split('private fun refreshJailbreakSelinuxHide()',1)[0]
assert 'UltraModulePolicyRepository.read(ksuApp)' in refresh and 'prepareSession' not in refresh
java=native_toolchain.jdk_tool('java')
deps=[cached_jar(*x) for x in [('org.jetbrains.kotlin','kotlin-stdlib','2.4.20'),('org.jetbrains','annotations','13.0'),('org.jetbrains.kotlinx','kotlinx-coroutines-core-jvm','1.11.0'),('junit','junit','4.13.2'),('org.hamcrest','hamcrest-core','1.3'),('org.json','json','20240303')]]
compiler=cached_jar('org.jetbrains.kotlin','kotlin-compiler-embeddable','2.4.20')
classes=a.out/'classes';cp=os.pathsep.join(map(str,[classes,*deps]));logs=[]
commands=[[java,'-Xmx512m','-cp',os.pathsep.join(map(str,[compiler,*deps])),'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler','-no-stdlib','-no-reflect','-jvm-target','21','-classpath',cp,'-d',classes,*sources,*stubs.glob('*.kt')],[java,'-Dfile.encoding=UTF-8','-cp',cp,'org.junit.runner.JUnitCore','dev.maplesu.manager.modules.HookPolicyBackendTest']]
for command in commands:
    r=subprocess.run(list(map(str,command)),cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=55)
    logs.append(r.stdout+r.stderr)
    if r.returncode:break
report=dict(generatedAt=datetime.now(timezone.utc).isoformat(),passed=r.returncode==0,exitCode=r.returncode,stdout='\n'.join(logs),sourceSha256={p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in [*sources,viewmodel,Path(__file__)]},settingsRefreshReadOnlyCallSite=True,scope='Real Kotlin orchestration/inventory and static settings call-site check; Android and Root are fixtures',deviceAccess=False)
(a.out/'acceptance.json').write_text(json.dumps(report,indent=2)+'\n');print(report['stdout']);raise SystemExit(r.returncode)
