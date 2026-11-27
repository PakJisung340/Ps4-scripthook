-- Contoh script: tulis posisi pemain ke scripthook.log tiap 3 detik.
-- Semua hash di bawah terverifikasi ada di tabel native PS4 (data/natives_ps4_cusa00419.csv).

local PLAYER_PED_ID     = 0xD80958FC74E988A6
local GET_ENTITY_COORDS = 0x3FEF770D40960D5A

CreateThread(function()
  log("example.lua jalan")
  while true do
    local ped = native.call(PLAYER_PED_ID, "i")
    local x, y, z = native.call(GET_ENTITY_COORDS, "v", ped, true)
    log(string.format("ped=%d  pos=%.1f %.1f %.1f", ped, x, y, z))
    Wait(3000)
  end
end)
