#pragma once

#include <d3d11.h>
#include <wincodec.h>
#include <cstdint>
#include <string>

namespace agy {

struct LoadedTexture {
    ID3D11ShaderResourceView* srv{ nullptr };
    int width{ 0 };
    int height{ 0 };

    bool is_valid() const { return srv != nullptr; }

    void release() {
        if (srv) {
            srv->Release();
            srv = nullptr;
        }
        width = 0;
        height = 0;
    }
};

class TextureLoader {
public:
    static bool load_from_file(ID3D11Device* device, const std::wstring& file_path, LoadedTexture& out_tex);
    static bool load_from_memory(ID3D11Device* device, const uint8_t* data, size_t size, LoadedTexture& out_tex);
    static bool load_from_resource(ID3D11Device* device, int resource_id, LoadedTexture& out_tex);
};

} // namespace agy

