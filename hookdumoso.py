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
        libso = Process.getModuleByName("libc.so");
        console.log("[name]:", libso.name);
        console.log("[base]:", libso.base);
        console.log("[size]:", ptr(libso.size));
        console.log("[path]:", libso.path);
        var file_path = "/sdcard/Download/" + libso.name + "_" + libso.base + "_" + ptr(libso.size) + ".so";
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            libso_buffer = Memory.readByteArray(libso.base, libso.size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("[dump]:", file_path);
        }
        
        name = "malloc";
        start=0xffff0000
        end=0xffff1000
        size=end-start
        var file_path = "/sdcard/Download/" + name + "_" + ptr(start) + "_" + ptr(size) + ".so";
        var file_handle = new File(file_path, "wb");
        if (file_handle && file_handle != null) {
            libso_buffer = Memory.readByteArray(ptr(start), size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            console.log("[dump]:", file_path);
        }
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
