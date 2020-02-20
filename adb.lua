-- https://wiki.wireshark.org/LuaAPI
-- https://www.cnblogs.com/zzqcn/p/4827337.html#_label1_2
-- https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
-- adb message dissector

local command = ProtoField.string("adb2.command", "command")
local local_id = ProtoField.uint32("adb2.local_id", "local id")
local remote_id = ProtoField.uint32("adb2.remote_id", "remote id")
local data_len = ProtoField.uint32("adb2.data_len", "data length")
local crc = ProtoField.uint32("adb2.crc", "data crc")
local magic = ProtoField.uint32("adb2.magic", "magic")
local data = ProtoField.bytes("adb2.data", "data")
local length_desc = ProtoField.string("adb.length_desc", "length")

local adb = Proto("adb2", "ADB Message")
adb.fields = {command, local_id, remote_id, data_len, crc, magic, data, length_desc}


function adb.dissector(tvb, pinfo, tree)
	local t = tree:add(adb, tvb())
	local p_command = tvb(0,4):string()
	local commands = {
		CNXN=true,
		SYNC=true,
		AUTH=true,
		OPEN=true,
		OKAY=true,
		CLSE=true,
		WRTE=true
	}
	if not commands[p_command]
	then
		local actual_len = 0
		actual_len = tvb:reported_len()
		local desc = string.format("%d[%d captured]", actual_len, tvb:len())
		pinfo.cols.protocol = "ADBData"
		if tostring(pinfo.src) == "host"
		then
			pinfo.cols.info = string.format(">>> %d bytes", actual_len)
		else
			pinfo.cols.info = string.format("<<< %s bytes", actual_len)
		end
		t:add(length_desc, desc)
		t:add(data, tvb())
		return
	end	
	
	t:add(command, tvb(0,4))
	local v_local_id = tvb(4, 4)
	t:add_le(local_id, v_local_id)
	local v_remote_id = tvb(8, 4)
	t:add_le(remote_id, v_remote_id)
	local v_data_len = tvb(12, 4)
	t:add_le(data_len, v_data_len)
	local v_crc = tvb(16, 4)
	t:add_le(crc, v_crc)
	local v_magic = tvb(20, 4)
	t:add_le(magic, v_magic)
	local v_data = tvb(24)
	if v_data:len() > 0
	then
		t:add(data, v_data)
	end
	pinfo.cols.protocol = "ADB"
	pinfo.cols.info = string.format("%s[%s bytes]", p_command, v_data_len:le_uint())
end

DissectorTable.get("tcp.port"):add("1-65535", adb)
DissectorTable.get("usb.device"):add("65536-65792",adb)