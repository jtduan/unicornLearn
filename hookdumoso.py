import frida
import sys

device = frida.get_usb_device()
session = device.attach("cn.jtduan.crack")

scr = """
console.log("Script loaded successfully ");
if(Java.available) {
    Java.perform(function () {
        var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
        var dir = currentApplication.getApplicationContext().getFilesDir().getPath();
        var libso = Process.getModuleByName("libnative-lib.so");
        console.log("[name]:", libso.name);
        console.log("[base]:", libso.base);
        console.log("[size]:", ptr(libso.size));
        console.log("[path]:", libso.path);
        var file_path = dir + "/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            Memory.protect(ptr(libso.base), libso.size, 'rwx');
            var libso_buffer = Memory.readByteArray(libso.base, libso.size);
            // var libso_buffer = ptr(libso.base).readByteArray(libso.size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("[dump]:", file_path);
        }
        var funcAddr = Module.findExportByName("libnative-lib.so","stringFromJNI")
        console.log("[funcAddr]:", funcAddr);
    });

}
"""


def on_message(message, data):
    if message["type"] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)


script = session.create_script(scr)
script.on("message", on_message)
script.load()
sys.stdin.read()
