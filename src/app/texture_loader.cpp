#include "texture_loader.hpp"
#include <windows.h>
#include <vector>

#pragma comment(lib, "windowscodecs.lib")

namespace agy {

bool TextureLoader::load_from_memory(ID3D11Device* device, const uint8_t* data, size_t size, LoadedTexture& out_tex) {
    if (!device || !data || size == 0) return false;

    IWICImagingFactory* factory = nullptr;
    HRESULT hr = CoCreateInstance(
        CLSID_WICImagingFactory,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&factory)
    );
    if (FAILED(hr) || !factory) return false;

    IWICStream* stream = nullptr;
    hr = factory->CreateStream(&stream);
    if (FAILED(hr) || !stream) {
        factory->Release();
        return false;
    }

    hr = stream->InitializeFromMemory(
        const_cast<BYTE*>(reinterpret_cast<const BYTE*>(data)),
        static_cast<DWORD>(size)
    );
    if (FAILED(hr)) {
        stream->Release();
        factory->Release();
        return false;
    }

    IWICBitmapDecoder* decoder = nullptr;
    hr = factory->CreateDecoderFromStream(
        stream,
        nullptr,
        WICDecodeMetadataCacheOnDemand,
        &decoder
    );
    if (FAILED(hr) || !decoder) {
        stream->Release();
        factory->Release();
        return false;
    }

    IWICBitmapFrameDecode* frame = nullptr;
    hr = decoder->GetFrame(0, &frame);
    if (FAILED(hr) || !frame) {
        decoder->Release();
        stream->Release();
        factory->Release();
        return false;
    }

    IWICFormatConverter* converter = nullptr;
    hr = factory->CreateFormatConverter(&converter);
    if (FAILED(hr) || !converter) {
        frame->Release();
        decoder->Release();
        stream->Release();
        factory->Release();
        return false;
    }

    hr = converter->Initialize(
        frame,
        GUID_WICPixelFormat32bppRGBA,
        WICBitmapDitherTypeNone,
        nullptr,
        0.0,
        WICBitmapPaletteTypeCustom
    );
    if (FAILED(hr)) {
        converter->Release();
        frame->Release();
        decoder->Release();
        stream->Release();
        factory->Release();
        return false;
    }

    UINT width = 0, height = 0;
    converter->GetSize(&width, &height);
    if (width == 0 || height == 0) {
        converter->Release();
        frame->Release();
        decoder->Release();
        stream->Release();
        factory->Release();
        return false;
    }

    std::vector<uint8_t> pixels(static_cast<size_t>(width) * height * 4);
    hr = converter->CopyPixels(
        nullptr,
        width * 4,
        static_cast<UINT>(pixels.size()),
        pixels.data()
    );

    converter->Release();
    frame->Release();
    decoder->Release();
    stream->Release();
    factory->Release();

    if (FAILED(hr)) return false;

    // Create D3D11 2D Texture
    D3D11_TEXTURE2D_DESC desc{};
    desc.Width = width;
    desc.Height = height;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.SampleDesc.Count = 1;
    desc.Usage = D3D11_USAGE_DEFAULT;
    desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;

    D3D11_SUBRESOURCE_DATA init_data{};
    init_data.pSysMem = pixels.data();
    init_data.SysMemPitch = width * 4;

    ID3D11Texture2D* texture = nullptr;
    hr = device->CreateTexture2D(&desc, &init_data, &texture);
    if (FAILED(hr) || !texture) return false;

    D3D11_SHADER_RESOURCE_VIEW_DESC srv_desc{};
    srv_desc.Format = desc.Format;
    srv_desc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
    srv_desc.Texture2D.MipLevels = 1;

    hr = device->CreateShaderResourceView(texture, &srv_desc, &out_tex.srv);
    texture->Release();

    if (FAILED(hr) || !out_tex.srv) return false;

    out_tex.width = static_cast<int>(width);
    out_tex.height = static_cast<int>(height);
    return true;
}

bool TextureLoader::load_from_resource(ID3D11Device* device, int resource_id, LoadedTexture& out_tex) {
    HMODULE hModule = GetModuleHandleW(nullptr);
    HRSRC hRes = FindResourceW(hModule, MAKEINTRESOURCEW(resource_id), MAKEINTRESOURCEW(10) /* RT_RCDATA */);
    if (!hRes) return false;

    HGLOBAL hGlobal = LoadResource(hModule, hRes);
    if (!hGlobal) return false;

    DWORD size = SizeofResource(hModule, hRes);
    const uint8_t* data = reinterpret_cast<const uint8_t*>(LockResource(hGlobal));
    if (!data || size == 0) return false;

    return load_from_memory(device, data, size, out_tex);
}

bool TextureLoader::load_from_file(ID3D11Device* device, const std::wstring& file_path, LoadedTexture& out_tex) {
    HANDLE hFile = CreateFileW(
        file_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD file_size = GetFileSize(hFile, nullptr);
    if (file_size == 0 || file_size == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    std::vector<uint8_t> buffer(file_size);
    DWORD bytes_read = 0;
    BOOL ok = ReadFile(hFile, buffer.data(), file_size, &bytes_read, nullptr);
    CloseHandle(hFile);

    if (!ok || bytes_read != file_size) return false;
    return load_from_memory(device, buffer.data(), buffer.size(), out_tex);
}

} // namespace agy

