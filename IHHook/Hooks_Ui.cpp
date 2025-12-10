#include "Hooks_Ui.h"
#include "hooks/mgsvtpp_func_typedefs.h"
#include "MinHook.h"
#include "spdlog/spdlog.h"
#include "spdlog/fmt/fmt.h"

#include <windows.h>
#include <atomic>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <climits>

#include <vector>
#include <mutex>
#include <algorithm>
#include <shared_mutex>

#include <string>
#include <winternl.h> // NTAPI, PVOID

#include "Hooks_Camo.h"
#pragma comment(lib, "ntdll") // not strictly required for GetProcAddress hook, harmless

namespace IHHook
{
    namespace Hooks_Ui
    {
        struct WindowInfo
        {
            fox::ui::Window* window{}; // fox::ui::Window*
            fox::ui::Window* parentWindow{}; // parent Window*
            fox::ui::WindowFunction* windowFunction{};
            fox::ui::WindowHandle* windowHandle{};
            std::vector<fox::ui::Layout*> layouts; // layouts owned by this window
            std::vector<fox::ui::Window*> children; // direct children in window graph

            fox::ui::Layout* attachLayout{}; // parent layout we hang from (if child)
            void* attachAnchor{}; // portPtr / node / slot pointer

            std::string windowName;
        };

        struct ModelInfo
        {
            fox::ui::ModelFileHeader* fileHeader{}; // *(model + 0x68)
            fox::StrCode32 modelName{}; // NewUiModelSharedPtr name
            fox::StrCode pathCode64{}; // optional: fill if you ever hook GetPathCode64s
            std::vector<fox::ui::ModelNode*> nodes; // collected in ReadUiModelNodeHook
        };

        static std::unordered_map<fox::ui::Window*, WindowInfo> g_windows; // window* -> info
        static std::unordered_map<void*, fox::ui::Window*> g_windowFuncToWindow;
        static std::unordered_map<fox::ui::WindowHandle*, fox::ui::Window*> g_handleToWindow; // handle -> window
        static std::unordered_map<fox::ui::Layout*, fox::ui::Window*> g_layoutToWindow; // layout* -> window

        // NEW: layouts seen per handle (WindowInterface). We bind these to a Window*
        // as soon as we learn handle->window.
        static std::unordered_map<const fox::ui::WindowInterface*, std::vector<fox::ui::Layout*>> g_ifaceLayouts;
        // key = WindowInterface*
        static std::unordered_map<fox::ui::WindowHandle*, std::vector<fox::ui::Layout*>> g_handleLayouts;

        static std::unordered_map<fox::ui::Model*, ModelInfo> g_modelInfo; // Model* -> info
        static std::unordered_map<fox::ui::ModelNode*, uint32_t> g_nodeNameByPtr; // ModelNode* -> StrCode32
        static std::unordered_map<fox::ui::ModelNode*, std::string> g_nodeTextByPtr; // ModelNode* -> last text

        static std::vector<fox::ui::Layout*> g_seenLayouts;
        static std::unordered_set<fox::ui::Layout*> g_seenLayoutsSet;
        static std::unordered_map<fox::ui::LayoutComponent*, fox::ui::Layout*> g_componentToLayout;

        static std::vector<fox::ui::Window*> g_seenWindows;
        static std::unordered_set<fox::ui::Window*> g_seenWindowSet;

        static std::mutex g_uiMutex;

        //TODO: Refactor into struct info
        static void* g_ModelNodeCommonlVtbl = reinterpret_cast<void*>(0x142553ea0);
        static void* g_ModelNodeMeshlVtbl = reinterpret_cast<void*>(0x142546910);
        static void* g_ModelNodeTextVtbl = reinterpret_cast<void*>(0x142544c80);
        static void* g_ModelNodeStencilVtbl = reinterpret_cast<void*>(0x1425540d0);
        static void* g_ModelNodeLineVtbl = reinterpret_cast<void*>(0x142546ab0);
        static void* g_ModelNodeVtbl = reinterpret_cast<void*>(0x142545d70); // ??
        static void* g_ModelVtbl = reinterpret_cast<void*>(0x142546240);
        static void* g_LayoutVtbl = reinterpret_cast<void*>(0x142543700);
        static void* g_WindowVtbl = reinterpret_cast<void*>(0x1425472b0);

        // ---------------------------------------------------------------------
        // Hooked Utils TODO: Pass these to struct
        // ---------------------------------------------------------------------

        struct ModelNodeWrapper
        {
            static constexpr void* vtbl = reinterpret_cast<void*>(0x142545d70);
            fox::ui::ModelNode* ptr{};

            explicit ModelNodeWrapper(fox::ui::ModelNode* p) : ptr(p)
            {
            }

            static bool isStruct(void* obj)
            {
                if (!obj) return false;
                void* objVtbl = *reinterpret_cast<void**>(obj);
                return objVtbl == vtbl;
            }
        };

        struct LayoutComponentWrapper
        {
            fox::ui::LayoutComponent* ptr{};

            LayoutComponentWrapper() = default;

            explicit LayoutComponentWrapper(fox::ui::LayoutComponent* p) : ptr(p)
            {
            }

            uint32_t GetComponentChildCount()
            {
                if (!ptr) return 0;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<uint32_t*>(base + 0x10);
            }

            fox::ui::LayoutComponent** GetComponentChildArray()
            {
                if (!ptr) return nullptr;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<fox::ui::LayoutComponent***>(base + 0x18);
            }

            fox::ui::LayoutComponent* GetComponentParent()
            {
                if (!ptr) return nullptr;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<fox::ui::LayoutComponent**>(base + 0x38);
            }

            const void* GetComponentPortNode() // fox::ui::ModelNode const*
            {
                if (!ptr) return nullptr;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<void* const*>(base + 0x40);
            }
        };

        struct ModelWrapper : LayoutComponentWrapper
        {
            static constexpr void* vtbl = reinterpret_cast<void*>(0x142546240);

            explicit ModelWrapper(fox::ui::Model* p) : LayoutComponentWrapper(p)
            {
            }

            static bool isStruct(void* obj)
            {
                if (!obj) return false;
                void* objVtbl = *reinterpret_cast<void**>(obj);
                return objVtbl == vtbl;
            }

            uint32_t GetModelNodeCountRaw()
            {
                if (!ptr) return 0;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<uint32_t*>(base + 0x90);
            }

            fox::ui::ModelNode** GetModelNodeArrayTyped()
            {
                if (!ptr) return nullptr;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<fox::ui::ModelNode***>(base + 0x98);
            }
        };

        struct LayoutWrapper : LayoutComponentWrapper
        {
            static constexpr void* vtbl = reinterpret_cast<void*>(0x142543700);
            fox::ui::Layout* ptr{};

            LayoutWrapper() = default;

            explicit LayoutWrapper(fox::ui::Layout* p) : ptr(p)
            {
            }

            static bool isStruct(void* obj)
            {
                if (!obj) return false;
                void* objVtbl = *reinterpret_cast<void**>(obj);
                return objVtbl == vtbl;
            }

            uint32_t GetModelCountRaw()
            {
                if (!ptr) return 0;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<uint32_t*>(base + 0xC0);
            }

            fox::ui::Model** GetModelArrayTyped()
            {
                if (!ptr) return nullptr;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<fox::ui::Model***>(base + 0xC8);
            }
        };

        struct WindowSlotEntry
        {
            void* slotObj; // 0x0
            int32_t prevIdx; // 0x8
            int32_t nextIdx; // 0xC
        };

        struct WindowWrapper
        {
            static constexpr void* vtbl = reinterpret_cast<void*>(0x1425472b0);
            fox::ui::Window* ptr{};

            WindowWrapper() = default;

            explicit WindowWrapper(fox::ui::Window* p) : ptr(p)
            {
            }

            static constexpr size_t kFlagsCountOff = 0x48;
            static constexpr size_t kHeadIdxOff = 0x50;
            static constexpr size_t kTailIdxOff = 0x54;
            static constexpr size_t kFreeIdxOff = 0x58;
            static constexpr size_t kSlotsBaseOff = 0x60;

            static bool isStruct(void* obj)
            {
                if (!obj) return false;
                void* objVtbl = *reinterpret_cast<void**>(obj);
                return objVtbl == vtbl;
            }

            WindowSlotEntry* GetSlots()
            {
                if (!ptr) return nullptr;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                return *reinterpret_cast<WindowSlotEntry**>(base + kSlotsBaseOff);
            }

            uint32_t GetCount()
            {
                if (!ptr) return 0;
                auto base = reinterpret_cast<uint8_t*>(ptr);
                uint32_t flagsCount = *reinterpret_cast<uint32_t*>(base + kFlagsCountOff);
                return (flagsCount & 0x7FFFFFFF);
            }

            fox::ui::Window* GetChildAt(uint32_t index)
            {
                if (!ptr) return nullptr;

                auto base = reinterpret_cast<uint8_t*>(ptr);
                auto slots = GetSlots();
                if (!slots) return nullptr;

                uint32_t headIdx = *reinterpret_cast<uint32_t*>(base + kHeadIdxOff);
                if (headIdx == 0xFFFFFFFFu) return nullptr;

                uint32_t curIdx = headIdx;
                uint32_t curPos = 0;

                while (curIdx != 0xFFFFFFFFu)
                {
                    WindowSlotEntry* e = &slots[curIdx];
                    auto slotObj = e->slotObj;

                    // first qword of slotObj is the child window (via Window::AddChild semantics)
                    auto childPtrPtr = reinterpret_cast<void**>(slotObj);
                    auto childWin = childPtrPtr ? reinterpret_cast<fox::ui::Window*>(*childPtrPtr) : nullptr;

                    if (curPos == index)
                        return childWin;

                    curIdx = e->nextIdx;
                    ++curPos;
                }

                return nullptr;
            }
        };
        
        static constexpr uint32_t kRootLayoutSid = 0x7FC4EBDD; // 2143611869
        static std::string GetTypeFor(void* val)
        {
            if (!val)
                return "Null";

            void* objVtbl = *reinterpret_cast<void**>(val);

            if (objVtbl == g_WindowVtbl)
            {
                return "Window";
            }
            if (objVtbl == g_LayoutVtbl)
            {
                return "Layout";
            }
            if (objVtbl == g_ModelVtbl)
            {
                return "Model";
            }
            if (objVtbl == g_ModelNodeCommonlVtbl)
            {
                return "ModelNodeCommon";
            }
            if (objVtbl == g_ModelNodeMeshlVtbl)
            {
                return "ModelNodeMesh";
            }
            if (objVtbl == g_ModelNodeStencilVtbl)
            {
                return "ModelNodeStencil";
            }
            if (objVtbl == g_ModelNodeLineVtbl)
            {
                return "ModelNodeLine";
            }
            if (objVtbl == g_ModelNodeTextVtbl)
            {
                return "ModelNodeText";
            }
            if (objVtbl == g_ModelNodeVtbl)
            {
                return "ModelNode";
            }

            return fmt::format("Unknown ({:p})", objVtbl);
        }

        static fox::ui::LayoutComponent* GetWindowRootLayoutComponent(fox::ui::Window* window)
        {
            if (!window) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(window);
            return *reinterpret_cast<fox::ui::LayoutComponent**>(base + 0x28);
        }

        static fox::ui::LayoutComponent* GetParentComponent(fox::ui::LayoutComponent* window)
        {
            if (!window) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(window);
            return *reinterpret_cast<fox::ui::LayoutComponent**>(base + 0x38);
        }


        static uint32_t GetComponentChildCount(void* comp)
        {
            if (!comp) return 0;
            auto base = reinterpret_cast<uint8_t*>(comp);
            return *reinterpret_cast<uint32_t*>(base + 0x10);
        }

        static fox::ui::LayoutComponent** GetComponentChildArray(void* comp)
        {
            if (!comp) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(comp);
            return *reinterpret_cast<fox::ui::LayoutComponent***>(base + 0x18);
        }

        static fox::ui::LayoutComponent* GetComponentParent(void* comp)
        {
            if (!comp) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(comp);
            return *reinterpret_cast<fox::ui::LayoutComponent**>(base + 0x38);
        }

        static const void* GetComponentPortNode(void* comp) // fox::ui::ModelNode const*
        {
            if (!comp) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(comp);
            return *reinterpret_cast<void* const*>(base + 0x40);
        }

        static bool GetNodeLocalVisible(const fox::ui::ModelNode* node)
        {
            if (!node) return false;
            auto base = reinterpret_cast<const uint8_t*>(node);
            auto flags = *reinterpret_cast<const uint16_t*>(base + 0x8);
            return (flags & 0x1) != 0;
        }

        static bool GetModelLocalVisible(fox::ui::Model* model)
        {
            if (!model) return false;
            auto base = reinterpret_cast<uint8_t*>(model);
            auto node = *reinterpret_cast<void**>(base + 0x80);
            return GetNodeLocalVisible(node);
        }

        static uint32_t GetModelNodeCountRaw(fox::ui::Model* model)
        {
            if (!model) return 0;
            auto base = reinterpret_cast<uint8_t*>(model);
            return *reinterpret_cast<uint32_t*>(base + 0x90);
        }

        static fox::ui::ModelNode** GetModelNodeArrayTyped(fox::ui::Model* model)
        {
            if (!model) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(model);
            return *reinterpret_cast<fox::ui::ModelNode***>(base + 0x98);
        }

        static uint32_t GetModelCountRaw(fox::ui::Layout* layout)
        {
            if (!layout) return 0;
            auto base = reinterpret_cast<uint8_t*>(layout);
            return *reinterpret_cast<uint32_t*>(base + 0xC0);
        }

        static fox::ui::Model** GetModelArrayTyped(fox::ui::Layout* layout)
        {
            if (!layout) return nullptr;
            auto base = reinterpret_cast<uint8_t*>(layout);
            return *reinterpret_cast<fox::ui::Model***>(base + 0xC8);
        }

        static bool GetModelLocalVisible(const fox::ui::Model* model)
        {
            if (!model) return false;
            auto base = reinterpret_cast<const uint8_t*>(model);
            auto node = *reinterpret_cast<void* const*>(base + 0x80);
            return GetNodeLocalVisible(node);
        }

        static bool GetNodeWorldVisible(const fox::ui::ModelNode* node)
        {
            if (!node) return false;

            // 1) local bit on self
            auto base  = reinterpret_cast<const uint8_t*>(node);
            auto flags = *reinterpret_cast<const uint16_t*>(base + 0x8);
            if ((flags & 0x1) == 0)
                return false;

            // 2) walk parents via [+0x10], same as asm
            const void* parent = *reinterpret_cast<void* const*>(base + 0x10);
            int depth = 0;

            while (parent && depth < 64) // depth guard in case of corrupted graphs
            {
                auto pBase  = reinterpret_cast<const uint8_t*>(parent);
                auto pFlags = *reinterpret_cast<const uint16_t*>(pBase + 0x8);
                if ((pFlags & 0x1) == 0)
                    return false;

                parent = *reinterpret_cast<void* const*>(pBase + 0x10);
                ++depth;
            }

            // if you hit nullptr parent, all bits in chain were 1 -> visible
            // if you break due to depth limit, treat as not visible to be safe
            return parent == nullptr;
        }

        static bool GetModelWorldVisible(const fox::ui::Model* model)
        {
            if (!model) return false;
            auto base = reinterpret_cast<const uint8_t*>(model);
            auto node = *reinterpret_cast<void* const*>(base + 0x80);
            return GetNodeWorldVisible(node);
        }

        
        static bool GetLayoutWorldVisible(const fox::ui::Layout* layout)
        {
            if (!layout) return false;
            auto* comp = reinterpret_cast<fox::ui::LayoutComponent*>(
                const_cast<fox::ui::Layout*>(layout));

            const void* portNode = GetComponentPortNode(comp);
            if (!portNode) return false;

            return GetNodeWorldVisible(portNode);
        }

        static bool GetLayoutComponentWorldVisible(const fox::ui::LayoutComponent* comp)
        {
            if (!comp) return false;
            const void* portNode = GetComponentPortNode(const_cast<fox::ui::LayoutComponent*>(comp));
            if (!portNode) return false;

            return GetNodeWorldVisible(portNode);
        }

        // bool IsValid(fox::ui::LayoutComponent* self) //TODO Might be useless to us
        // {
        //     auto* first = *reinterpret_cast<longlong**>(self + 0x18);
        //     auto* last  = first + *reinterpret_cast<uint32_t*>(self + 0x10);
        //
        //     while (true)
        //     {
        //         if (first == last)
        //             return true;   // all used entries non-null
        //
        //         if (*first == 0)
        //             break;         // found a nullptr in the active range
        //
        //         ++first;
        //     }
        //
        //     return false;
        // }

        static fox::StrCode32 GetLayoutSid(fox::ui::Layout* layout)
        {
            if (!layout) return 0;
            auto base = reinterpret_cast<uint8_t*>(layout);
            return *reinterpret_cast<fox::StrCode32*>(base + 0x20);
        }

        static fox::StrCode32 GetModelNodeNameSid(const fox::ui::ModelNode* node)
        {
            if (!node) return 0;

            auto base = reinterpret_cast<const uint8_t*>(node);
            return *reinterpret_cast<const fox::StrCode32*>(base + 0x6C);
        }

        static uint8_t GetModelNodeTypeRaw(const fox::ui::ModelNode* node)
        {
            if (!node) return 0xFF;

            auto base = reinterpret_cast<const uint8_t*>(node);
            return *reinterpret_cast<const uint8_t*>(base + 0x72);
        }

        enum ModelNodeType : uint8_t
        {
            MODEL_NODE_TYPE_ROOT = 0x0,	
            MODEL_NODE_TYPE_COMMON = 0x1,
            MODEL_NODE_TYPE_MESH = 0x2,
            MODEL_NODE_TYPE_TEXT = 0x3,
            MODEL_NODE_TYPE_STENCIL = 0x4,
            MODEL_NODE_TYPE_LINE = 0x5,
            MODEL_NODE_TYPE_INVALID = 0x6
            // others unknown for now
        };

        std::string GetModelNodeHumanReadableType(const fox::ui::ModelNode* node)
        {
            switch (GetModelNodeTypeRaw(node))
            {
                case MODEL_NODE_TYPE_ROOT: return "ROOT";
                case MODEL_NODE_TYPE_COMMON: return "COMMON";
                case MODEL_NODE_TYPE_MESH: return "MESH";
                case MODEL_NODE_TYPE_TEXT: return "TEXT";
                case MODEL_NODE_TYPE_STENCIL: return "STENCIL";
                case MODEL_NODE_TYPE_LINE: return "LINE";
                default: return "INVALID";
            }
        }

        static ModelNodeType GetModelNodeType(const fox::ui::ModelNode* node)
        {
            return static_cast<ModelNodeType>(GetModelNodeTypeRaw(node));
        }

        static void DumpNodeBinaryRaw(const fox::ui::ModelNode* node, int maxBytes = 0x40)
        {
            if (!node) return;
            auto base = reinterpret_cast<const uint8_t*>(node);
            auto bin  = *reinterpret_cast<const uint8_t* const*>(base + 0x60);
            if (!bin) return;

            ModelNodeType type = GetModelNodeType(node);
            spdlog::info("    [BIN] node={} type={} bin={}",
                         static_cast<const void*>(node),
                         static_cast<int>(type),
                         static_cast<const void*>(bin));

            // For now: dumb hex dump by type, then line it up with uif.bt manually.
            int len = maxBytes;
            std::string hex;
            for (int i = 0; i < len; ++i) {
                hex += fmt::format("{:02X} ", bin[i]);
            }
            spdlog::info("      [BIN RAW] {}", hex);
        }

        static bool GetWindowWorldVisible(const fox::ui::Window* w)
        {
            if (!w) return false;

            auto* rootComp = GetWindowRootLayoutComponent(const_cast<fox::ui::Window*>(w));
            if (!rootComp) return false;

            const void* portNode = GetComponentPortNode(rootComp);
            if (!portNode) return false;

            return GetNodeWorldVisible(portNode);
        }

        struct WindowChildren
        {
            static constexpr size_t kFlagsCountOff = 0x48;
            static constexpr size_t kHeadIdxOff = 0x50;
            static constexpr size_t kTailIdxOff = 0x54;
            static constexpr size_t kFreeIdxOff = 0x58;
            static constexpr size_t kSlotsBaseOff = 0x60;

            static WindowSlotEntry* GetSlots(fox::ui::Window* w)
            {
                if (!w) return nullptr;
                auto base = reinterpret_cast<uint8_t*>(w);
                return *reinterpret_cast<WindowSlotEntry**>(base + kSlotsBaseOff);
            }

            static uint32_t GetCount(fox::ui::Window* w)
            {
                if (!w) return 0;
                auto base = reinterpret_cast<uint8_t*>(w);
                uint32_t flagsCount = *reinterpret_cast<uint32_t*>(base + kFlagsCountOff);
                return (flagsCount & 0x7FFFFFFF);
            }

            static fox::ui::Window* GetChildAt(fox::ui::Window* w, uint32_t index)
            {
                if (!w) return nullptr;

                auto base = reinterpret_cast<uint8_t*>(w);
                auto slots = GetSlots(w);
                if (!slots) return nullptr;

                uint32_t headIdx = *reinterpret_cast<uint32_t*>(base + kHeadIdxOff);
                if (headIdx == 0xFFFFFFFFu) return nullptr;

                uint32_t curIdx = headIdx;
                uint32_t curPos = 0;

                while (curIdx != 0xFFFFFFFFu)
                {
                    WindowSlotEntry* e = &slots[curIdx];
                    void* slotObj = e->slotObj;
                    fox::ui::Window* childWin = nullptr;

                    if (slotObj)
                    {
                        // Case 1: slotObj itself is a Window*
                        if (GetTypeFor(slotObj) == "Window")
                        {
                            childWin = reinterpret_cast<fox::ui::Window*>(slotObj);
                        }
                        else
                        {
                            // Case 2: slotObj is a pointer to a Window*
                            auto* asPtrToPtr = reinterpret_cast<void**>(slotObj);
                            void* maybeWin = asPtrToPtr ? *asPtrToPtr : nullptr;

                            if (maybeWin && GetTypeFor(maybeWin) == "Window")
                                childWin = reinterpret_cast<fox::ui::Window*>(maybeWin);
                        }
                    }

                    if (curPos == index)
                        return childWin;

                    curIdx = e->nextIdx;
                    ++curPos;
                }

                return nullptr;
            }
        };
        
        static std::string FoxStringToStd(const fox::String* s)
        {
            if (!s || !s->cString)
                return {};

            auto raw = static_cast<int64_t>(s->length);

            if (raw <= 0 || raw > 0x10000)
                return std::string(s->cString);  // strlen fallback

            return std::string(s->cString, static_cast<size_t>(raw));
        }
        
        static std::string BytesToHex(const void* data, size_t size)
        {
            if (!data || size == 0)
                return {};

            const uint8_t* p = static_cast<const uint8_t*>(data);
            std::string out;
            out.reserve(size * 3);

            static const char* hex = "0123456789ABCDEF";

            for (size_t i = 0; i < size; ++i)
            {
                if (i)
                    out.push_back(' ');

                uint8_t b = p[i];
                out.push_back(hex[b >> 4]);
                out.push_back(hex[b & 0x0F]);
            }

            return out;
        }

        static std::string FoxStringToHex(const fox::String* s, size_t maxBytes = 64)
        {
            if (!s || !s->cString)
                return {};

            const uint8_t* bytes = reinterpret_cast<const uint8_t*>(s->cString);
            size_t len = 0;

            auto raw = static_cast<int64_t>(s->length);

            if (raw > 0 && raw <= static_cast<int64_t>(maxBytes))
                len = static_cast<size_t>(raw);
            else if (raw > 0)
                len = static_cast<size_t>(std::min<int64_t>(raw, maxBytes));
            else
                len = maxBytes; // unknown / sentinel length, just dump prefix

            return BytesToHex(bytes, len);
        }


        // ---------------------------------------------------------------------
        // Hooks
        // ---------------------------------------------------------------------

        static void DumpModelNodes_Direct(void* modelPtr, const std::string& indent)
        {
            auto* model = reinterpret_cast<fox::ui::Model*>(modelPtr);
            if (!model) return;

            uint32_t count = GetModelNodeCountRaw(model);
            auto** nodes = GetModelNodeArrayTyped(model);

            // spdlog::info(
            //     "{}[MODEL] model={} visible={} nodeCount={} realType={}",
            //     indent,
            //     static_cast<const void*>(model),
            //     GetModelWorldVisible(model),
            //     count,
            //     GetTypeFor(model)
            // );

            if (!nodes) return;

            const std::string nodeIndent = indent + "  ";

            for (uint32_t i = 0; i < count; ++i)
            {
                auto* node = nodes[i];
                if (!node) continue;

                uint32_t nameSid = 0;
                std::string text;
                {
                    std::lock_guard<std::mutex> lock(g_uiMutex);

                    auto itName = g_nodeNameByPtr.find(node);
                    if (itName != g_nodeNameByPtr.end())
                        nameSid = itName->second;

                    auto itText = g_nodeTextByPtr.find(node);
                    if (itText != g_nodeTextByPtr.end())
                        text = itText->second;
                }

                std::string shortText = text;
                if (shortText.size() > 80)
                {
                    shortText.resize(80);
                    shortText += "...";
                }

                if (!shortText.empty())
                {
                    spdlog::info(
                        "{}[NODE] idx={} node={} visible={} type={} sid=#{:08X} realType={} text=\"{}\"",
                        nodeIndent,
                        static_cast<int>(i),
                        static_cast<const void*>(node),
                        GetNodeWorldVisible(node),
                        GetModelNodeHumanReadableType(node),
                        GetModelNodeNameSid(node),
                        GetTypeFor(node),
                        shortText
                    );
                }
                else
                {
                    spdlog::info(
                        "{}[NODE] idx={} node={} visible={} type={} sid=#{:08X} realType={}",
                        nodeIndent,
                        static_cast<int>(i),
                        static_cast<const void*>(node),
                        GetNodeWorldVisible(node),
                        GetModelNodeHumanReadableType(node),
                        GetModelNodeNameSid(node),
                        GetTypeFor(node)
                    );
                }
            }
        }

        static void DumpLayoutForWindow(fox::ui::Layout* layout,
                                        fox::ui::Window* ownerWindow,
                                        const std::string& windowName,
                                        int depth)
        {
            if (!layout)
                return;

            // {
            //     std::lock_guard<std::mutex> lock(g_uiMutex);
            //     if (!IsKnownLayout_NoLock(layout))
            //     {
            //         spdlog::info("[LAYOUT DUMP SKIP] layout={} (not in seenLayoutsSet)",
            //                      static_cast<const void*>(layout));
            //         return;
            //     }
            // }

            auto* base = reinterpret_cast<uint8_t*>(layout);
            void** modelArr = *reinterpret_cast<void***>(base + 0xC8);
            uint32_t mCount = *reinterpret_cast<uint32_t*>(base + 0xC0);

            std::string indent(depth * 2, ' ');

            spdlog::info(
                "{}[LAYOUT] layout={} modelArr={} modelCount={} ownerWindow={} windowName=\"{}\" realType={}",
                indent,
                static_cast<const void*>(layout),
                static_cast<const void*>(modelArr),
                mCount,
                static_cast<const void*>(ownerWindow),
                windowName,
                GetTypeFor(layout)
            );

            if (!modelArr || !mCount)
            {
                spdlog::info("{}  [MODEL] <none>", indent);
                return;
            }

            for (uint32_t i = 0; i < mCount; ++i)
            {
                void* modelPtr = modelArr[i];
                if (!modelPtr)
                    continue;

                spdlog::info(
                    "{}  [MODEL IDX] {} -> {}",
                    indent,
                    i,
                    static_cast<const void*>(modelPtr)
                );

                DumpModelNodes_Direct(modelPtr, indent + "    ");
            }
        }

        static void SetLayoutOwner_NoLock(fox::ui::Layout* layout,
                                          fox::ui::Window* w,
                                          const char* reason)
        {
            if (!layout || !w)
                return;

            g_layoutToWindow[layout] = w;

            auto& info = g_windows[w];
            info.window = w;

            auto& lv = info.layouts;
            if (std::find(lv.begin(), lv.end(), layout) == lv.end())
                lv.push_back(layout);

            spdlog::debug("[LAYOUT OWNER] layout={} window={} reason={}",
                          static_cast<const void*>(layout),
                          static_cast<const void*>(w),
                          reason ? reason : "");
        }

        static void BindHandleLayoutsToWindow_NoLock(fox::ui::WindowHandle* handle,
                                                     fox::ui::Window* w)
        {
            if (!handle || !w)
                return;

            auto it = g_handleLayouts.find(handle);
            if (it == g_handleLayouts.end())
                return;

            auto& layouts = it->second;
            auto& info = g_windows[w];
            info.window = w;
            info.windowHandle = handle;

            for (auto* L : layouts)
            {
                if (!L)
                    continue;

                SetLayoutOwner_NoLock(L, w, "BindHandleLayoutsToWindow");
            }
        }

        static void DumpWindowRecursive(fox::ui::Window* w,
                                        const std::unordered_map<fox::ui::Window*, WindowInfo>& windows,
                                        int depth)
        {
            auto it = windows.find(w);
            if (it == windows.end())
                return;

            const WindowInfo& info = it->second;
            std::string indent(depth * 2, ' ');

            spdlog::info(
                "{}[WIN] window={} parent={} handle={} func={} name=\"{}\" anchorLayout={} anchorPort={} realType={}",
                indent,
                static_cast<const void*>(info.window),
                static_cast<const void*>(info.parentWindow),
                static_cast<const void*>(info.windowHandle),
                static_cast<const void*>(info.windowFunction),
                info.windowName,
                static_cast<const void*>(info.attachLayout),
                info.attachAnchor,
                GetTypeFor(w)
            );

            // Layouts belonging to this window
            for (auto* layout : info.layouts)
            {
                DumpLayoutForWindow(layout, info.window, info.windowName, depth + 1);
            }

            // Recurse into children
            for (auto* child : info.children)
            {
                DumpWindowRecursive(child, windows, depth + 1);
            }
        }

        static void DumpWindowAndLayoutTree()
        {
            std::unordered_map<fox::ui::Window*, WindowInfo> windowsCopy;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                windowsCopy = g_windows; // value copy: safe snapshot
            }

            spdlog::info("========== UI WINDOW / LAYOUT / MODEL TREE ==========");
            spdlog::info("  windows tracked: {}", windowsCopy.size());

            // Root windows = no parent, or parent not in map
            for (auto& kv : windowsCopy)
            {
                fox::ui::Window* w = kv.first;
                const WindowInfo& info = kv.second;

                if (!info.parentWindow || windowsCopy.find(info.parentWindow) == windowsCopy.end())
                {
                    DumpWindowRecursive(w, windowsCopy, 0);
                }
            }

            spdlog::info("========== END UI WINDOW / LAYOUT / MODEL TREE ==========");
        }

        static void TrackLayout_NoLock(fox::ui::Layout* layout)
        {
            if (!layout) return;

            if (g_seenLayoutsSet.insert(layout).second)
            {
                g_seenLayouts.push_back(layout);
                spdlog::info("[TRACK LAYOUT] layout={}", static_cast<const void*>(layout));
            }
        }

        static void TrackLayout(fox::ui::Layout* layout)
        {
            if (!layout) return;

            std::lock_guard<std::mutex> lock(g_uiMutex);
            TrackLayout_NoLock(layout);
        }

        static void TrackWindow_NoLock(fox::ui::Window* w)
        {
            if (!w) return;
            if (g_seenWindowSet.insert(w).second)
            {
                g_seenWindows.push_back(w);
                spdlog::info("[TRACK WINDOW] window={}", static_cast<const void*>(w));
            }
        }

        static void TrackWindow(fox::ui::Window* w)
        {
            std::lock_guard<std::mutex> lock(g_uiMutex);
            TrackWindow_NoLock(w);
        }

        // Scan a layoutInfo blob for pointers that match known Layout*
        static std::vector<fox::ui::Layout*> ScanLayoutInfoForLayouts_NoLock(const void* layoutInfo)
        {
            std::vector<fox::ui::Layout*> out;
            if (!layoutInfo)
                return out;

            const uint8_t* base = reinterpret_cast<const uint8_t*>(layoutInfo);

            // Conservative scan range, can be extended if needed
            constexpr size_t kMaxScan = 0x80;

            for (size_t off = 0; off + sizeof(void*) <= kMaxScan; off += sizeof(void*))
            {
                auto candidate = *reinterpret_cast<fox::ui::Layout* const*>(base + off);
                if (!candidate)
                    continue;

                if (g_seenLayoutsSet.find(candidate) == g_seenLayoutsSet.end())
                    continue;

                if (std::find(out.begin(), out.end(), candidate) == out.end())
                    out.push_back(candidate);
            }

            return out;
        }

        static void DumpOrphanLayouts()
        {
            std::vector<fox::ui::Layout*> layoutsCopy;
            std::unordered_map<fox::ui::Layout*, fox::ui::Window*> layoutToWindowCopy;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                layoutsCopy = g_seenLayouts;
                layoutToWindowCopy = g_layoutToWindow;
            }

            spdlog::info("========== ORPHAN LAYOUTS (no owning Window) ==========");
            spdlog::info("  orphans tracked: {} / {}", layoutsCopy.size() - layoutToWindowCopy.size(),
                         layoutsCopy.size());

            for (auto* layout : layoutsCopy)
            {
                if (!layout)
                    continue;

                auto it = layoutToWindowCopy.find(layout);
                if (it != layoutToWindowCopy.end() && it->second)
                    continue; // already owned, skip here

                DumpLayoutForWindow(layout, nullptr, "<ORPHAN>", 0);
            }

            spdlog::info("========== END ORPHAN LAYOUTS ==========");
        }

        static void BucketLayoutForIfaceAndHandle_NoLock(const void* ifaceOrHandle,
                                                         fox::ui::Layout* layout)
        {
            if (!ifaceOrHandle || !layout)
                return;

            auto* iface = reinterpret_cast<const fox::ui::WindowInterface*>(ifaceOrHandle);
            auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(const_cast<void*>(ifaceOrHandle));

            auto pushUnique = [layout](auto& vec)
            {
                if (std::find(vec.begin(), vec.end(), layout) == vec.end())
                    vec.push_back(layout);
            };

            // Track under both the interface view and the handle view
            pushUnique(g_ifaceLayouts[iface]);
            pushUnique(g_handleLayouts[handle]);

            // If we already know which window this handle belongs to, bind immediately.
            auto itWin = g_handleToWindow.find(handle);
            if (itWin != g_handleToWindow.end() && itWin->second)
            {
                BindHandleLayoutsToWindow_NoLock(handle, itWin->second);
            }
        }

        static void AttachRootLayoutForWindow_NoLock(fox::ui::Window* w, const char* reason)
        {
            if (!w)
                return;

            auto* root = GetWindowRootLayoutComponent(w); // window + 0x28
            if (!root)
                return;

            // Only adopt if we already know this pointer as a Layout
            if (g_seenLayoutsSet.find(root) == g_seenLayoutsSet.end())
            {
                spdlog::debug("[ROOT LAYOUT SKIP] window={} rawRoot={} reason={}",
                              static_cast<const void*>(w),
                              static_cast<const void*>(root),
                              reason ? reason : "");
                return;
            }

            // Make sure it's tracked & owned
            TrackLayout_NoLock(root);
            SetLayoutOwner_NoLock(root, w, reason ? reason : "RootLayout");
        }

        static void DumpLayoutComponentRecursive(
            fox::ui::LayoutComponent* comp,
            int depth,
            std::unordered_set<fox::ui::LayoutComponent*>& visited)
        {
            if (!comp) return;
            if (!visited.insert(comp).second) return; // already printed in this walk

            std::string indent(depth * 2, ' ');

            void* vtbl = *reinterpret_cast<void**>(comp);
            auto* parent = GetComponentParent(comp);
            auto* portNode = reinterpret_cast<const fox::ui::ModelNode*>(GetComponentPortNode(comp));

            uint32_t childCount = GetComponentChildCount(comp);
            auto** children = GetComponentChildArray(comp);

            uint32_t portSid = 0;
            std::string portText;

            if (portNode)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto itName = g_nodeNameByPtr.find(const_cast<fox::ui::ModelNode*>(portNode));
                if (itName != g_nodeNameByPtr.end())
                    portSid = itName->second;

                auto itText = g_nodeTextByPtr.find(const_cast<fox::ui::ModelNode*>(portNode));
                if (itText != g_nodeTextByPtr.end())
                    portText = itText->second;
            }

            if (portText.size() > 80)
            {
                portText.resize(80);
                portText += "...";
            }

            if (vtbl == g_LayoutVtbl)
            {
                auto* layout = reinterpret_cast<fox::ui::Layout*>(comp);

                uint32_t sid = GetLayoutSid(layout);
                spdlog::info(
                    "{}[{}] comp={} visible={} type={} sid=#{:08X} parent={} children={} portNode={} portSid=#{:08X} portText=\"{}\"",
                    indent,
                    (sid == kRootLayoutSid ? "ROOT LAYOUT" : "LAYOUT"), 
                    static_cast<const void*>(layout),
                    GetLayoutWorldVisible(layout),
                    GetTypeFor(layout),
                    sid,
                    static_cast<const void*>(parent),
                    childCount,
                    static_cast<const void*>(portNode),
                    portSid,
                    portText
                );
            }
            else if (vtbl == g_ModelVtbl)
            {
                auto* model = reinterpret_cast<fox::ui::Model*>(comp);
                uint32_t nodeCount = GetModelNodeCountRaw(model);

                spdlog::info(
                    "{}[MODEL] comp={} visible={} type={} sid=#{:08X} parent={} children={} nodes={} portNode={} portSid=#{:08X} portText=\"{}\"",
                    indent,
                    static_cast<const void*>(model),
                    GetModelWorldVisible(model),
                    GetTypeFor(model),
                    GetLayoutSid(model),
                    static_cast<const void*>(parent),
                    childCount,
                    nodeCount,
                    static_cast<const void*>(portNode),
                    portSid,
                    portText
                );

                // Only here do we introspect nodes
                DumpModelNodes_Direct(model, indent);
            }
            else
            {
                spdlog::info(
                    "{}[COMP] comp={} type={} parent={} children={} portNode={} portSid=#{:08X} portText=\"{}\"",
                    indent,
                    static_cast<const void*>(comp),
                    GetTypeFor(comp),
                    static_cast<const void*>(parent),
                    childCount,
                    static_cast<const void*>(portNode),
                    portSid,
                    portText
                );
            }

            if (!children || !childCount)
                return;

            for (uint32_t i = 0; i < childCount; ++i)
            {
                auto* child = children[i];
                if (!child) continue;
                DumpLayoutComponentRecursive(child, depth + 1, visited);
            }
        }

        static void DumpRawWindowRecursive(
            fox::ui::Window* w,
            const std::unordered_map<fox::ui::Window*, std::vector<fox::ui::Window*>>& slotChildren,
            int depth,
            std::unordered_set<fox::ui::Window*>& visited)
        {
            if (!w) return;
            if (!visited.insert(w).second) return; // avoid cycles

            std::string indent(depth * 2, ' ');

            uint32_t slotChildCount = WindowChildren::GetCount(w);
            auto* rootComp = GetWindowRootLayoutComponent(w);

            spdlog::info(
                "{}[WINDOW] window={} visible={} type={} sid=#{:08X} slotChildCount={} rootComp={} rootType={}",
                indent,
                static_cast<const void*>(w),
                GetWindowWorldVisible(w),
                GetTypeFor(w),
                GetLayoutSid(w),
                slotChildCount,
                static_cast<const void*>(rootComp),
                GetTypeFor(rootComp));

            if (rootComp)
            {
                std::unordered_set<fox::ui::LayoutComponent*> visitedComp;
                DumpLayoutComponentRecursive(rootComp, depth + 1, visitedComp);
            }
            else
            {
                spdlog::info("{}  [COMP ROOT] <none>", indent);
            }

            auto it = slotChildren.find(w);
            if (it == slotChildren.end())
                return;

            for (auto* child : it->second)
                DumpRawWindowRecursive(child, slotChildren, depth + 1, visited);
        }

        static void DumpWindowSlotViewTreeFromSeenWindows()
        {
            std::vector<fox::ui::Window*> windows;
            std::unordered_set<fox::ui::Window*> knownWindows;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                windows = g_seenWindows;
                knownWindows = g_seenWindowSet;
            }

            spdlog::info("========== WINDOW SLOT / COMPONENT TREE (F10, raw) ==========");
            spdlog::info("  windows tracked (seen): {}", windows.size());

            if (windows.empty())
            {
                spdlog::info("  <no windows in g_seenWindows>");
                spdlog::info("========== END WINDOW SLOT / COMPONENT TREE (F10, raw) ==========");
                return;
            }

            std::unordered_map<fox::ui::Window*, std::vector<fox::ui::Window*>> slotChildren;
            std::unordered_map<fox::ui::Window*, fox::ui::Window*> slotParent;

            // Build parent/child purely from WindowSlots, but clamp to the seen-window set
            for (auto* w : windows)
            {
                if (!w) continue;

                uint32_t count = WindowChildren::GetCount(w);
                for (uint32_t i = 0; i < count; ++i)
                {
                    auto* child = WindowChildren::GetChildAt(w, i);
                    if (!child) continue;
                    if (!knownWindows.count(child)) continue; // F10 = “from collected windows alone”
                    if (child == w) continue;

                    auto& vec = slotChildren[w];
                    if (std::find(vec.begin(), vec.end(), child) == vec.end())
                        vec.push_back(child);

                    if (!slotParent.count(child))
                        slotParent[child] = w;
                }
            }

            // Roots = seen windows that never appear as a child in this slot graph
            std::vector<fox::ui::Window*> roots;
            roots.reserve(windows.size());
            for (auto* w : windows)
            {
                if (!w) continue;
                if (slotParent.find(w) == slotParent.end())
                    roots.push_back(w);
            }

            if (roots.empty())
                roots = windows; // degenerate case: cycles or no parent info

            std::unordered_set<fox::ui::Window*> visited;
            for (auto* root : roots)
                DumpRawWindowRecursive(root, slotChildren, 0, visited);

            // Any seen window not hit via the slot graph gets dumped as an orphan
            for (auto* w : windows)
            {
                if (!w) continue;
                if (visited.count(w)) continue;

                spdlog::info("[WIN_ORPHAN] window={} (no slot parent/children)",
                             static_cast<const void*>(w));

                auto* rootComp = GetWindowRootLayoutComponent(w);
                if (rootComp)
                {
                    std::unordered_set<fox::ui::LayoutComponent*> visitedComp;
                    DumpLayoutComponentRecursive(rootComp, 1, visitedComp);
                }
            }

            spdlog::info("========== END WINDOW SLOT / COMPONENT TREE (F10, raw) ==========");
        }

        // ---------------------------------------------------------------------
        // Hooks
        // ---------------------------------------------------------------------

        // text hooks
        void __fastcall SetTextForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, const char* rawText,
                                                    bool isLocalized)
        {
            if (rawText)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeTextByPtr[reinterpret_cast<fox::ui::ModelNode*>(nodeText)] = rawText;
            }

            spdlog::debug("[STFMNT] uix={} nodeText={} textUnit={} rawText={} isLocalized={}",
                          uix, nodeText, textUnit, rawText ? rawText : "", isLocalized);

            SetTextForModelNodeText(uix, nodeText, textUnit, rawText, isLocalized);
        }

        void __fastcall SetTextForModelNodeTextInternalHook(void* nodeText, void* textUnit, const char* rawText,
                                                            bool isLocalized)
        {
            if (rawText)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeTextByPtr[reinterpret_cast<fox::ui::ModelNode*>(nodeText)] = rawText;
            }

            spdlog::debug("[STFMNTI] nodeText={} textUnit={} rawText={} isLocalized={}", nodeText, textUnit,
                          rawText, isLocalized);
            SetTextForModelNodeTextInternal(nodeText, textUnit, rawText, isLocalized); // original
        }

        void __fastcall SetTextUnitsForModelNodeTextHook(void* uix, void* nodeText, void* textUnit, uint64_t stringId)
        {
            const char* resolved = nullptr;
            if (uix && stringId)
            {
                resolved = GetManagerText(uix, static_cast<fox::StrCode32>(stringId));
                if (resolved)
                {
                    std::lock_guard<std::mutex> lock(g_uiMutex);
                    g_nodeTextByPtr[reinterpret_cast<fox::ui::ModelNode*>(nodeText)] = resolved;
                }
            }

            spdlog::debug("[STUFMNT] uix={} nodeText={} textUnit={} stringId={} text={}",
                          uix,
                          static_cast<const void*>(nodeText),
                          textUnit,
                          stringId,
                          resolved ? resolved : "");

            SetTextUnitsForModelNodeText(uix, nodeText, textUnit, stringId);
        }

        bool __fastcall SetTextUnitsHook(void* nodeText, void* textUnit, uint64_t stringId)
        {
            bool ok = SetTextUnits(nodeText, textUnit, stringId);
            spdlog::debug("[STU] retBool={} nodeText={} textUnit={} stringId={}", ok, nodeText, textUnit, stringId);
            return ok;
        }

        // visibility hooks
        void __fastcall SetNodeVisibilityWrapperHook(void* anyMgr, void* node, bool visible)
        {
            SetNodeVisibilityWrapper(anyMgr, node, visible);
        }

        void __fastcall SetNodeVisibilityHook(void* node, bool visible)
        {
            SetNodeVisibility(node, visible);
        }

        bool __fastcall IsNodeVisibleHook(void* anyMgr, void* node)
        {
            return IsNodeVisible(anyMgr, node);
        }

        void* __fastcall NodeConnectShimHook(void* owner, void* parentComp, void* portPtr, void* childArg)
        {
            spdlog::debug("[NCS] owner={} parentComp={} portPtr={} childArg={}",
                          owner, parentComp, portPtr, childArg);

            return NodeConnectShim(owner, parentComp, portPtr, childArg);
        }

        fox::ui::Layout* __fastcall LayoutGetLayoutHook(fox::ui::Layout* self, int layoutId)
        {
            auto retLayout = LayoutGetLayout(self, layoutId);

            if (retLayout)
            {
                TrackLayout(retLayout);

                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto itW = g_layoutToWindow.find(self);
                if (itW != g_layoutToWindow.end() && itW->second)
                {
                    SetLayoutOwner_NoLock(retLayout, itW->second, "LayoutGetLayout");
                }
            }

            spdlog::debug("[LayoutGetLayout] retLayout={} self={} layoutId={}",
                         static_cast<const void*>(retLayout),
                         static_cast<const void*>(self),
                         layoutId);

            return retLayout;
        }

        // This function is shared between multiple components and it simply returns self + 0x28 TODO: Generic rename
        fox::ui::Layout* __fastcall GetWindowInterfaceLayoutHook(fox::ui::WindowInterface* self)
        {
            auto* layout = GetWindowInterfaceLayout(self); // original (self + 0x28 helper)
            if (!self || !layout)
                return layout;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // In this function, `self` is a WindowInterface* (or handle),
                // NOT a fox::ui::Window*, so comparing its vtbl to g_WindowVtbl is wrong.

                fox::ui::Window* w = nullptr;

                // First, assume it's actually a WindowHandle-based interface
                auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(self);
                auto itH = g_handleToWindow.find(handle);
                if (itH != g_handleToWindow.end())
                    w = itH->second;

                // Fallback: sometimes a Window* is passed directly as the interface
                if (!w)
                {
                    auto* asWindow = reinterpret_cast<fox::ui::Window*>(self);
                    auto itW = g_windows.find(asWindow);
                    if (itW != g_windows.end())
                        w = itW->second.window;
                }

                if (w)
                {
                    // Optionally track, then bind
                    TrackLayout_NoLock(layout);
                    SetLayoutOwner_NoLock(layout, w, "GetWindowInterfaceLayout");
                }
            }

            spdlog::debug("[GetWindowInterfaceLayout] self={} layout={} type={} retType={}",
                          static_cast<const void*>(self),
                          static_cast<const void*>(layout), GetTypeFor(self), GetTypeFor(layout));

            return layout;
        }


        // Model discovery
        fox::ui::Model* __fastcall GetModelWrapperHook(fox::ui::Layout* layout, fox::ui::Model** outModel,
                                                       fox::StrCode32 strCode)
        {
            auto retModel = GetModelWrapper(layout, outModel, strCode);

            spdlog::debug("[GetModelWrapperHook] retModel={} layout={} sid32=#{:08X}",
                         retModel, layout, (uint32_t)strCode);
            return retModel;
        }

        void* __fastcall GetModelNodeFromIndexHook(const void* model, int index)
        {
            return GetModelNodeFromIndex(model, index);
        }

        void* __fastcall GetModelNodeCommonHook(void* selfModel)
        {
            return GetModelNodeCommon(selfModel);
        }

        void* __fastcall GetModelNodeCommonInternalHook(void* selfModel, uint64_t sid)
        {
            spdlog::debug("[GetModelNodeCommonInternalHook] GetModelNodeCommonInternal model={} sid32=#{:08X}",
                          selfModel, (uint32_t)sid);
            return GetModelNodeCommonInternal(selfModel, sid);
        }

        bool __fastcall IsHaveModelNodeCommonHook(void* selfUixUtility, const void* model, fox::StrCode stringId)
        {
            spdlog::debug("[IsHaveModelNodeCommonHook] IsHaveModelNodeCommon model={} sid32=#{:08X}",
                          model, stringId);
            return IsHaveModelNodeCommon(selfUixUtility, model, stringId);
        }

        // lifecycle
        void __fastcall OnLayoutComponentDestroyHook(void* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto base = *reinterpret_cast<void**>(self);
                spdlog::debug("[OnLayoutComponentDestroy] captured LayoutComponent vtbl={} type={}", base,
                             GetTypeFor(self));
                g_componentToLayout.erase(reinterpret_cast<fox::ui::LayoutComponent*>(self));
            }

            OnLayoutComponentDestroy(self);
        }

        // Creation ctx harvest
        void* __fastcall NewUiModelTextHook(uint32_t sceneStr, void* creationCtx, void* a2, void* a3)
        {
            auto ret = NewUiModelText(sceneStr, creationCtx, a2, a3);
            spdlog::debug("[NewUiModelText] node={} sceneStr=#{:08X} ctx={}", ret, sceneStr, creationCtx);

            return ret;
        }

        fox::SharedPtr<fox::ui::Model>* __fastcall NewUiModelSharedPtrHook(
            fox::SharedPtr<fox::ui::Model>* outPtr, fox::FilePtr* file, fox::StrCode32 name, uint64_t unused_or_flags)
        {
            auto ret = NewUiModelSharedPtr(outPtr, file, name, unused_or_flags);

            fox::ui::Model* model = outPtr ? outPtr->Object : nullptr;
            if (model)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto& info = g_modelInfo[model];
                info.modelName = name;
            }

            spdlog::debug("[NewUiModelSharedPtr] model={} file={} name=#{:08X} flags={}",
                         static_cast<void*>(model),
                         static_cast<void*>(file),
                         static_cast<uint32_t>(name),
                         unused_or_flags);
            return ret;
        }

        fox::SharedPtr<fox::ui::Layout>* __fastcall NewUiLayoutSharedPtrHook(
            fox::SharedPtr<fox::ui::Layout>* outPtr, uint32_t flags)
        {
            auto ret = NewUiLayoutSharedPtr(outPtr, flags);

            fox::ui::Layout* layout = (outPtr ? outPtr->Object : nullptr);
            if (layout)
            {
                TrackLayout(layout);
                spdlog::debug("[NewUiLayoutSharedPtr] layout={} flags={}",
                              static_cast<const void*>(layout),
                              flags);
            }

            return ret;
        }

        fox::ui::ModelNode* __fastcall UiModelNodeCtorHook(fox::ui::ModelNode* self, fox::StrCode32 name)
        {
            auto ret = UiModelNodeCtor(self, name);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeNameByPtr[self] = name;
            }
            spdlog::debug("[UiModelNodeCtor] node={} name=#{:08X}",
                         static_cast<void*>(self),
                         static_cast<uint32_t>(name));

            return ret;
        }

        fox::ui::Layout* __fastcall LayoutCtorHook(fox::ui::Layout* self, uint32_t layoutFlags)
        {
            auto ret = LayoutCtor(self, layoutFlags);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                TrackLayout_NoLock(self);
            }

            spdlog::debug("[LayoutCtor] ret={} self={} flags={}",
                          static_cast<void*>(ret),
                          static_cast<void*>(self),
                          layoutFlags);

            return ret;
        }

        fox::ui::Model* __fastcall ModelCtorHook(fox::ui::Model* self, fox::FilePtr* file, fox::StrCode32 name)
        {
            auto ret = ModelCtor(self, file, name);

            spdlog::debug("[ModelCtor] ret={} self={} file={} name={}",
                          static_cast<void*>(ret),
                          static_cast<void*>(self),
                          static_cast<void*>(file),
                          name);

            return ret;
        }

        void __fastcall LayoutDtorHook(fox::ui::Layout* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // 1) Remove from global layout tracking
                {
                    auto it = g_seenLayoutsSet.find(self);
                    if (it != g_seenLayoutsSet.end())
                        g_seenLayoutsSet.erase(it);

                    auto itV = std::remove(g_seenLayouts.begin(), g_seenLayouts.end(), self);
                    if (itV != g_seenLayouts.end())
                        g_seenLayouts.erase(itV, g_seenLayouts.end());
                }

                // 2) Remove from layout -> window map
                g_layoutToWindow.erase(self);

                // 3) Remove from every WindowInfo.layouts
                for (auto& kv : g_windows)
                {
                    auto& lv = kv.second.layouts;
                    auto itL = std::remove(lv.begin(), lv.end(), self);
                    if (itL != lv.end())
                        lv.erase(itL, lv.end());
                }

                // 4) Remove from handle -> layouts buckets
                for (auto& kv : g_handleLayouts)
                {
                    auto& vec = kv.second;
                    auto itL = std::remove(vec.begin(), vec.end(), self);
                    if (itL != vec.end())
                        vec.erase(itL, vec.end());
                }

                // 5) Remove from iface -> layouts buckets
                for (auto& kv : g_ifaceLayouts)
                {
                    auto& vec = kv.second;
                    auto itL = std::remove(vec.begin(), vec.end(), self);
                    if (itL != vec.end())
                        vec.erase(itL, vec.end());
                }
            }

            LayoutDtor(self);
            spdlog::debug("[LayoutDtor] self={}", static_cast<void*>(self));
        }

        void __fastcall ModelDtorHook(fox::ui::Model* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_modelInfo.erase(self); // model -> info
            }
            ModelDtor(self);
            spdlog::debug("[ModelDtor] self={}", static_cast<void*>(self));
        }

        void __fastcall ModelNodeDtorHook(fox::ui::ModelNode* self)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                g_nodeNameByPtr.erase(self); // node -> name32
                g_nodeTextByPtr.erase(self); // node -> text
            }

            ModelNodeDtor(self);
            spdlog::debug("[ModelNodeDtor] self={}", static_cast<void*>(self));
        }

        // window plumbing hooks
        void __fastcall UpdateWindowGraphHook(void* selfWindow)
        {
            UpdateWindowGraph(selfWindow);
        }

        void __fastcall AddChildWindowHook(fox::ui::Window* selfWindow, fox::ui::Window* childWindow)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto& parentInfo = g_windows[selfWindow];
                parentInfo.window = selfWindow;

                // dedupe children
                auto& children = parentInfo.children;
                if (std::find(children.begin(), children.end(), childWindow) == children.end())
                {
                    children.push_back(childWindow);
                }

                auto& childInfo = g_windows[childWindow];
                childInfo.window = childWindow;
                childInfo.parentWindow = selfWindow;
            }

            spdlog::debug("[AddChildWindow] parent={} child={}", static_cast<void*>(selfWindow),
                         static_cast<void*>(childWindow));

            AddChildWindow(selfWindow, childWindow);
        }

        void __fastcall RemoveChildWindowHook(fox::ui::Window* selfWindow, fox::ui::Window* childWindow)
        {
            // Let engine do the real detach first.
            RemoveChildWindow(selfWindow, childWindow);

            if (!childWindow)
                return;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // 1) Remove child from parent's children vector
                auto itParent = g_windows.find(selfWindow);
                if (itParent != g_windows.end())
                {
                    auto& children = itParent->second.children;
                    auto it = std::remove(children.begin(), children.end(), childWindow);
                    if (it != children.end())
                        children.erase(it, children.end());
                }

                // 2) Clear child's parentWindow + anchor info
                auto itChild = g_windows.find(childWindow);
                if (itChild != g_windows.end())
                {
                    auto& childInfo = itChild->second;
                    childInfo.parentWindow = nullptr;
                    childInfo.attachLayout = nullptr;
                    childInfo.attachAnchor = nullptr;
                }
            }

            spdlog::debug("[RemoveChildWindow] parent={} child={}",
                         static_cast<void*>(selfWindow),
                         static_cast<void*>(childWindow));
        }

        void* __fastcall CreateNewWindowHook(void* cls /*WindowFunction*/, const void* nameStr, uint32_t flagsA,
                                             uint32_t flagsB)
        {
            return CreateNewWindow(cls, nameStr, flagsA, flagsB);
        }

        void* __fastcall GetWindowManagerHook()
        {
            return GetWindowManager();
        }

        void* __fastcall GetWindowLayoutHook(void* windowFunction, uint64_t layoutId)
        {
            void* L = GetWindowLayout(windowFunction, layoutId);

            if (L)
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                fox::ui::Window* w = nullptr;

                // windowFunction is the same "resourceCreator" you stored in WindowCtorHook
                auto it = g_windowFuncToWindow.find(windowFunction);
                if (it != g_windowFuncToWindow.end())
                    w = it->second;

                if (w)
                {
                    auto* layout = reinterpret_cast<fox::ui::Layout*>(L);
                    SetLayoutOwner_NoLock(layout, w, "GetWindowLayout");
                }
            }

            return L;
        }

        void* __fastcall FindWindowFactoryHook(void* collector, int hash)
        {
            return FindWindowFactory(collector, hash);
        }

        void __fastcall RegisterWindowFactoryHook(void* collector, void* factory)
        {
            RegisterWindowFactory(collector, factory);
        }

        void* __fastcall GetWindowHandleHook(void* mgr, void* windowFunction)
        {
            auto h = GetWindowHandle(mgr, windowFunction);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                fox::ui::Window* w = nullptr;

                auto it = g_windowFuncToWindow.find(windowFunction);
                if (it != g_windowFuncToWindow.end())
                    w = it->second;
                else
                {
                    auto* asWindow = reinterpret_cast<fox::ui::Window*>(windowFunction);
                    auto it2 = g_windows.find(asWindow);
                    if (it2 != g_windows.end())
                        w = it2->second.window;
                }

                auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(h);

                if (w && handle)
                {
                    g_handleToWindow[handle] = w;

                    auto& info = g_windows[w];
                    info.window = w;
                    info.windowHandle = handle;

                    spdlog::debug("[WIN HANDLE] handle={} window={}",
                                  static_cast<const void*>(handle),
                                  static_cast<const void*>(w));

                    // NEW: root layout opportunistic bind
                    AttachRootLayoutForWindow_NoLock(w, "GetWindowHandle_root");

                    BindHandleLayoutsToWindow_NoLock(handle, w);
                }
            }

            return h;
        }

        fox::String* __fastcall GetWindowNameHook(fox::ui::Window* self)
        {
            auto name = GetWindowName(self);

            return name;
        }

        fox::ui::Window* __fastcall WindowCtorHook(fox::ui::Window* self,
                                                   fox::ui::WindowFunction* resourceCreator,
                                                   fox::String* name,
                                                   uint32_t type,
                                                   fox::ui::WindowResourceCreator** creatorIface,
                                                   uint16_t zOrder,
                                                   uint32_t groupId,
                                                   uint32_t updateMask)
        {
            auto window = WindowCtor(self, resourceCreator, name, type, creatorIface, zOrder, groupId, updateMask);

            uint64_t hash = name ? name->hash : 0;
            std::string nameStr;
            if (name && hash != 0)
                nameStr = FoxStringToStd(name);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto& info = g_windows[window];
                info.window = window;
                info.windowFunction = resourceCreator;
                if (!nameStr.empty())
                    info.windowName = nameStr;

                g_windowFuncToWindow[resourceCreator] = window;

                // NEW: root layout opportunistic bind
                AttachRootLayoutForWindow_NoLock(window, "WindowCtor_root");

                // NEW: raw tracking, independent of WindowInfo semantics
                TrackWindow_NoLock(window);
            }

            spdlog::debug(
                "[WIN CTOR] retWin={} self={} resourceCreator={} name=\"{}\" hash=#{:016X} type={} creatorIface={} zOrder={} groupId={} updateMask={}",
                static_cast<void*>(window),
                static_cast<void*>(self),
                static_cast<void*>(resourceCreator),
                nameStr,
                hash,
                type,
                static_cast<void*>(creatorIface),
                zOrder,
                groupId,
                updateMask);

            return window;
        }

        void __fastcall WindowDtorHook(fox::ui::Window* self)
        {
            // Call the real destructor first so engine can do its thing.
            WindowDtor(self);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // 1) Drop this window from any parent->children lists
                for (auto& kv : g_windows)
                {
                    auto& vec = kv.second.children;
                    auto it = std::remove(vec.begin(), vec.end(), self);
                    if (it != vec.end())
                        vec.erase(it, vec.end());
                }

                // 2) Erase its own WindowInfo entry
                g_windows.erase(self);

                // 3) Remove from windowFunction -> window map
                for (auto it = g_windowFuncToWindow.begin(); it != g_windowFuncToWindow.end();)
                {
                    if (it->second == self)
                        it = g_windowFuncToWindow.erase(it);
                    else
                        ++it;
                }

                // 4) Remove from handle -> window map
                for (auto it = g_handleToWindow.begin(); it != g_handleToWindow.end();)
                {
                    if (it->second == self)
                        it = g_handleToWindow.erase(it);
                    else
                        ++it;
                }

                {
                    auto it = g_seenWindowSet.find(self);
                    if (it != g_seenWindowSet.end())
                        g_seenWindowSet.erase(it);

                    auto itV = std::remove(g_seenWindows.begin(), g_seenWindows.end(), self);
                    if (itV != g_seenWindows.end())
                        g_seenWindows.erase(itV, g_seenWindows.end());
                }

                spdlog::debug("[WIN DTOR] cleaned self={}", static_cast<void*>(self));
            }
        }

        void __fastcall ProcessWindowHook(fox::ui::Window* self,
                                          const uint32_t* msg,
                                          const uint64_t* arg0,
                                          const uint64_t* arg1)
        {
            spdlog::debug("[PROCESS WIN] self={} msg={} arg0={} arg1={}",
                          static_cast<void*>(self),
                          static_cast<const void*>(msg),
                          static_cast<const void*>(arg0),
                          static_cast<const void*>(arg1));
            ProcessWindow(self, msg, arg0, arg1);
        }

        fox::ui::Window* __fastcall FindChildWindowHook(const fox::ui::Window* self, fox::StrCode32 id)
        {
            auto childWin = FindChildWindow(self, id);
            spdlog::debug("[FIND CHILD WIN] retWin={} self={} id={}",
                          static_cast<void*>(childWin),
                          static_cast<const void*>(self),
                          id);
            return childWin;
        }

        fox::ui::Window* __fastcall FindUiWindowHook(fox::StrCode32 id)
        {
            auto retWin = FindUiWindow(id);
            spdlog::debug("[FIND WIN] retWin={} id={}",
                          static_cast<void*>(retWin),
                          id);
            return retWin;
        }

        void __fastcall UpdateWindowLayoutsHook(fox::ui::WindowManager* self, fox::StrCode32 groupId)
        {
            spdlog::debug("[UPDATE WINDOW LAYOUT] sekf={} id={}",
                          static_cast<void*>(self),
                          groupId);
            UpdateWindowLayouts(self, groupId);
        }

        void __fastcall SetLayoutInfoHook(void* windowHandle, const void* layoutInfo)
        {
            // Call the real thing first to keep engine semantics intact
            SetLayoutInfo(windowHandle, layoutInfo);

            fox::ui::Window* w = nullptr;
            std::vector<fox::ui::Layout*> layouts;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto* handle = reinterpret_cast<fox::ui::WindowHandle*>(windowHandle);

                // Resolve handle -> window if we already know it
                auto itWin = g_handleToWindow.find(handle);
                if (itWin != g_handleToWindow.end())
                    w = itWin->second;

                // Find any Layout* embedded in layoutInfo that are already tracked
                layouts = ScanLayoutInfoForLayouts_NoLock(layoutInfo);

                // Bucket layouts under this handle for later binding if window not known yet
                if (handle && !layouts.empty())
                {
                    auto& bucket = g_handleLayouts[handle];
                    for (auto* L : layouts)
                    {
                        if (!L)
                            continue;
                        if (std::find(bucket.begin(), bucket.end(), L) == bucket.end())
                            bucket.push_back(L);
                    }
                }

                // If we already know the window, immediately mark ownership
                if (w && !layouts.empty())
                {
                    for (auto* L : layouts)
                    {
                        if (!L)
                            continue;
                        SetLayoutOwner_NoLock(L, w, "SetLayoutInfo_scan");
                    }
                }
            }

            spdlog::debug(
                "[SetLayoutInfo] handle={} layoutInfo={} window={} layoutsCount={} firstLayout={}",
                windowHandle,
                layoutInfo,
                static_cast<const void*>(w),
                layouts.size(),
                layouts.empty() ? nullptr : static_cast<const void*>(layouts[0]));
        }

        void* __fastcall GetTextUnitsHook(int index)
        {
            void* tu = GetTextUnits(index); // original
            spdlog::debug("[GET TU] index={} -> {}", index, tu);
            return tu;
        }

        void* __fastcall GetTextUnitsInternalHook(void* fontMgr, int index)
        {
            void* tu = GetTextUnitsInternal(fontMgr, index); // original
            spdlog::debug("[GET TUI] fontMgr={} index={} -> {}", fontMgr, index, tu);
            return tu;
        }

        void __fastcall SetTextUnitHook(void* selfTextUnit, char* text, uint32_t flags, uint16_t p3, uint16_t p4,
                                        float size, float tracking, uint32_t p7, uint32_t p8)
        {
            SetTextUnit(selfTextUnit, text, flags, p3, p4, size, tracking, p7, p8);
            spdlog::debug("[SET TU] selfTextUnit={} text={} flags={} p3={} p4={} size={} tracking={} p7={} p8={}",
                          selfTextUnit, text, flags, p3, p4, size, tracking, p7, p8);
        }

        void __fastcall DeleteTextUnitHook(void* uixImpl, void* textUnit)
        {
            DeleteTextUnit(uixImpl, textUnit);
        }

        int __fastcall CreateBoxTextHook(void* modelNodeText, void* textUnit, uint32_t unitId,
                                         char* text, bool a, bool b)
        {
            return CreateBoxText(modelNodeText, textUnit, unitId, text, a, b);
        }

        void __fastcall GraphUpdateHook(void* selfGraph)
        {
            // spdlog::info("[GRAPH UPDATE] selfGraph={}", selfGraph);

            GraphUpdate(selfGraph);
        }

        fox::ui::Layout* __fastcall GetUixLayoutHook(void* manager, const fox::ui::WindowInterface* windowIface,
                                                     fox::StrCode layoutId)
        {
            auto* layout = GetUixLayout(manager, windowIface, layoutId);
            if (!layout)
                return nullptr;

            TrackLayout(layout);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                BucketLayoutForIfaceAndHandle_NoLock(windowIface, layout);
            }

            spdlog::debug("[GetUixLayout] mgr={} iface={} layoutId=#{:08X} layout={}",
                         manager, windowIface, (uint32_t)layoutId, layout);

            return layout;
        }

        void* __fastcall GetGlobalUixUtilityHook()
        {
            auto uix = GetGlobalUixUtility();
            // spdlog::debug("[GLOBAL UIX] Uix={}", uix);
            return uix;
        }


        // Window / layout connects (FIELD route)
        void __fastcall ConnectLayoutComponentHook(void* childComp, void* parentComp, void* portPtr)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto it = g_componentToLayout.find(parentComp);
                if (it != g_componentToLayout.end())
                {
                    g_componentToLayout[childComp] = it->second;
                }
            }

            spdlog::info("[CLC] childComp={} childType={} parentComp={} parentType={} portPtr={}",
                         childComp, GetTypeFor(childComp), parentComp, GetTypeFor(parentComp), portPtr);
            ConnectLayoutComponent(childComp, parentComp, portPtr);
        }

        void __fastcall ConnectLayoutUtilityComponentHook(void* childComp, void* parentComp, fox::StrCode portSid)
        {
            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto it = g_componentToLayout.find(parentComp);
                if (it != g_componentToLayout.end())
                {
                    g_componentToLayout[childComp] = it->second;
                }
            }

            spdlog::info("[CLU] child={} childType={} parent={} parentType={} portSid=#{:08X}",
                         static_cast<const void*>(childComp),
                         GetTypeFor(childComp),
                         static_cast<const void*>(parentComp),
                         GetTypeFor(parentComp),
                         portSid);

            // spdlog::debug("[CLU] childComp={} parentComp={} portSid=#{:08X}",
            //               childComp, parentComp, portSid);

            ConnectLayoutUtilityComponent(childComp, parentComp, portSid);
        }

        bool __fastcall CreateChildWindowsHook(void* creator, fox::ui::Window* parentWin)
        {
            bool ok = CreateChildWindows(creator, parentWin);

            return ok;
        }

        void __fastcall ConnectChildWindowToNodeHook(fox::ui::Window* parentWin, fox::ui::WindowHandle* childHandle,
                                                     fox::ui::LayoutComponent* parentComp, void* portPtr)
        {
            fox::ui::Layout* layout = nullptr;
            fox::ui::Window* childWin = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // Resolve child from handle
                auto itChild = g_handleToWindow.find(childHandle);
                if (itChild != g_handleToWindow.end())
                    childWin = itChild->second;
                else
                    childWin = reinterpret_cast<fox::ui::Window*>(childHandle);

                // Resolve layout for this LayoutComponent
                auto itLayout = g_componentToLayout.find(parentComp);
                if (itLayout != g_componentToLayout.end())
                {
                    layout = itLayout->second;

                    // Parent owns this layout
                    if (parentWin && layout)
                        SetLayoutOwner_NoLock(layout, parentWin, "ConnectChildWindowToNode");
                }

                if (childWin)
                {
                    auto& childInfo = g_windows[childWin];
                    childInfo.window = childWin;
                    childInfo.parentWindow = parentWin;
                    childInfo.attachLayout = layout;
                    childInfo.attachAnchor = portPtr;

                    if (parentWin)
                    {
                        auto& parentInfo = g_windows[parentWin];
                        parentInfo.window = parentWin;

                        auto& children = parentInfo.children;
                        if (std::find(children.begin(), children.end(), childWin) == children.end())
                            children.push_back(childWin);
                    }
                }
            }

            spdlog::debug(
                "[ANCHOR] parentWin={} childHandle={} parentComp={} parentType={} portPtr={} layout={} childWin={}",
                static_cast<const void*>(parentWin),
                static_cast<const void*>(childHandle),
                static_cast<const void*>(parentComp),
                GetTypeFor(parentComp),
                portPtr,
                static_cast<const void*>(layout),
                static_cast<void*>(childWin));

            ConnectChildWindowToNode(parentWin, childHandle, parentComp, portPtr);
        }

        void __fastcall ConnectChildWindowToRootHook(fox::ui::Window* parentWin, fox::ui::WindowHandle* childHandle)
        {
            fox::ui::Window* childWin = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto it = g_handleToWindow.find(childHandle);
                if (it != g_handleToWindow.end())
                    childWin = it->second;
                else
                    childWin = reinterpret_cast<fox::ui::Window*>(childHandle);

                if (childWin)
                {
                    auto& childInfo = g_windows[childWin];
                    childInfo.window = childWin;
                    childInfo.parentWindow = parentWin;
                    childInfo.windowHandle = childHandle;

                    auto& parentInfo = g_windows[parentWin];
                    parentInfo.window = parentWin;

                    auto& children = parentInfo.children;
                    if (std::find(children.begin(), children.end(), childWin) == children.end())
                        children.push_back(childWin);

                    g_handleToWindow[childHandle] = childWin;

                    spdlog::info("[ROOT HANDLE] parentWin={} childHandle={} childWin={}",
                                 static_cast<const void*>(parentWin),
                                 static_cast<const void*>(childHandle),
                                 static_cast<const void*>(childWin));

                    // NEW: root layout bind on both parent and child
                    AttachRootLayoutForWindow_NoLock(parentWin, "ConnectChildWindowToRoot_parent");
                    AttachRootLayoutForWindow_NoLock(childWin, "ConnectChildWindowToRoot_child");

                    BindHandleLayoutsToWindow_NoLock(childHandle, childWin);
                }
                else
                {
                    spdlog::info("[ROOT HANDLE] parentWin={} childHandle={} (no childWin)",
                                 static_cast<const void*>(parentWin),
                                 static_cast<const void*>(childHandle));
                }
            }

            ConnectChildWindowToRoot(parentWin, childHandle);
        }

        void* __fastcall GetConnectModelHook(void* self /*ModelNodeConnection**/, void* outTransform /*=nullptr*/)
        {
            auto ret = GetConnectModel(self, outTransform);
            spdlog::debug("[GetConnectModel] model={} self={} outTransform={}", ret, self, outTransform);
            return ret;
        }

        void __fastcall ConnectWindowToParentHook(void* windowFunction, void* parentComp, void* portPtr)
        {
            fox::ui::Window* ownerWindow = nullptr;
            fox::ui::Layout* layout = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // WindowFunction* -> Window* (original assumption)
                auto itWin = g_windowFuncToWindow.find(windowFunction);
                if (itWin != g_windowFuncToWindow.end())
                    ownerWindow = itWin->second;

                // Fallback: maybe windowFunction is actually a Window*
                if (!ownerWindow)
                {
                    auto* asWindow = reinterpret_cast<fox::ui::Window*>(windowFunction);
                    auto itW2 = g_windows.find(asWindow);
                    if (itW2 != g_windows.end())
                        ownerWindow = itW2->second.window;
                }

                // LayoutComponent* -> Layout*
                auto itLayout = g_componentToLayout.find(
                    reinterpret_cast<fox::ui::LayoutComponent*>(parentComp));
                if (itLayout != g_componentToLayout.end())
                    layout = itLayout->second;

                if (ownerWindow && layout)
                {
                    SetLayoutOwner_NoLock(layout, ownerWindow, "ConnectWindowToParent");
                }
            }

            spdlog::info("[CWP] windowFunc={} parentComp={} portPtr={} window={} layout={}",
                         windowFunction,
                         parentComp,
                         portPtr,
                         static_cast<const void*>(ownerWindow),
                         static_cast<const void*>(layout));

            ConnectWindowToParent(windowFunction, parentComp, portPtr);
        }

        void __fastcall SetModelNodeTextDisplayWidthHook(void* nodeText, float width)
        {
            spdlog::debug("[SetModelNodeTextDisplayWidth] nodeText={} width={}", nodeText, width);
            SetModelNodeTextDisplayWidth(nodeText, width);
        }

        void __fastcall SetModelNodeTextDisplayHeightHook(void* nodeText, float height)
        {
            spdlog::debug("[SetModelNodeTextDisplayHeight] nodeText={} width={}", nodeText, height);
            SetModelNodeTextDisplayHeight(nodeText, height);
        }

        void __fastcall SetUixModelNodeTextFontSizeHook(void* uix, void* nodeText, float px, float secondary)
        {
            spdlog::debug("[SetUixModelNodeTextFontSize] uix={} modelNodeText={} px={} secondary={}", uix, nodeText, px,
                          secondary);
            SetUixModelNodeTextFontSize(uix, nodeText, px, secondary);
        }

        void __fastcall SetModelNodeTextFontSizeHook(void* nodeText, float px, float secondary)
        {
            spdlog::debug("[SetModelNodeTextFontSize] modelNodeText={} px={} secondary={}", nodeText, px, secondary);
            SetModelNodeTextFontSize(nodeText, px, secondary);
        }

        void __fastcall SetModelNodeTextFontSpaceHook(void* nodeText, float px, float secondary)
        {
            spdlog::debug("[SetModelNodeTextFontSpace] modelNodeText={} px={} secondary={}", nodeText, px, secondary);
            SetModelNodeTextFontSpace(nodeText, px, secondary);
        }

        void __fastcall SetModelNodeTextColorRGBHook(void* uix, void* nodeText, float r, float g, float b)
        {
            spdlog::debug("[SetModelNodeTextColorRGB] uix={} nodeText={} r={} g={} b={}", uix, nodeText, r, g, b);
            SetModelNodeTextColorRGB(uix, nodeText, r, g, b);
        }

        void __fastcall ResetModelNodeTextFontSizeHook(void* nodeText)
        {
            spdlog::debug("[ResetModelNodeTextFontSize] nodeText={}", nodeText);
            ResetModelNodeTextFontSize(nodeText);
        }

        void __fastcall ResetModelNodeTextFontSpaceHook(void* nodeText)
        {
            spdlog::debug("[ResetModelNodeTextFontSpace] nodeText={}", nodeText);
            ResetModelNodeTextFontSpace(nodeText);
        }

        bool __fastcall GetModelNodeWorldVisibilityHook(const void* node)
        {
            return GetModelNodeWorldVisibility(node);
        }

        void __fastcall BuildTextAreaPackHook(void* modelNodeText, TextAreaPack* out)
        {
            BuildTextAreaPack(modelNodeText, out);
        }

        void __fastcall ApplyTextAndMeasureHook(fox::ui::ActSetText* act, fox::ui::ModelNode* node, void* unitsCtx, void* fmtCtx)
        {
            ApplyTextAndMeasure(act, node, unitsCtx, fmtCtx);

            spdlog::info("[ACT SET TEXT APPLY] self={} node={}", act, node);
        }

        void __fastcall RunAnalysisHook(ActSetText* self)
        {
            RunAnalysis(self);
        }

        void __fastcall SetModelNodeTextDisplayAreaWidthOffsetHook(void* nodeText, float addWidth, float addOffset)
        {
            SetModelNodeTextDisplayAreaWidthOffset(nodeText, addWidth, addOffset);
        }

        void __fastcall LayoutConnectHook(void* uiUtil, fox::ui::WindowHandle* windowIface,
                                          fox::StrCode sidA, fox::StrCode sidB,
                                          fox::StrCode sidModel, fox::StrCode sidPort)
        {
            // First, let the engine wire everything
            LayoutConnect(uiUtil, windowIface, sidA, sidB, sidModel, sidPort);

            if (!windowIface)
                return;

            // Root layout under this interface
            auto* rootLayout =
                GetUixLayout(uiUtil, windowIface, sidA); // same 'this', same iface, sidA as the id
            if (!rootLayout)
                return;

            int idB = static_cast<int>(static_cast<uint32_t>(sidB));
            fox::ui::Layout* layoutB = LayoutGetLayout(rootLayout, idB);

            TrackLayout(rootLayout);
            if (layoutB) TrackLayout(layoutB);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                BucketLayoutForIfaceAndHandle_NoLock(windowIface, rootLayout);
                BucketLayoutForIfaceAndHandle_NoLock(windowIface, layoutB);
            }

            spdlog::debug(
                "[LayoutConnect] uiUtil={} iface={} sidA=#{:08X} sidB=#{:08X} sidModel=#{:08X} sidPort=#{:08X} root={} B={}",
                uiUtil,
                windowIface,
                (uint32_t)sidA,
                (uint32_t)sidB,
                (uint32_t)sidModel,
                (uint32_t)sidPort,
                static_cast<const void*>(rootLayout),
                static_cast<const void*>(layoutB));
        }


        fox::ui::Window* __fastcall WindowCreateHook(const fox::ui::WindowResourceCreator* rc,
                                                     const fox::String* name, uint32_t flags,
                                                     fox::ui::Window* parent,
                                                     uint16_t zOrder,
                                                     uint32_t opt6,
                                                     uint32_t opt7)
        {
            auto w = WindowCreate(rc, name, flags, parent, zOrder, opt6, opt7);

            uint64_t hash = name ? name->hash : 0;
            std::string nameStr;
            if (name && hash != 0)
                nameStr = FoxStringToStd(name);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                auto& info = g_windows[w];
                info.window = w;
                info.parentWindow = parent;
                info.windowFunction = const_cast<fox::ui::WindowResourceCreator*>(rc);
                if (!nameStr.empty())
                    info.windowName = nameStr;

                // NEW: root layout opportunistic bind
                AttachRootLayoutForWindow_NoLock(w, "WindowCreate_root");
            }

            spdlog::debug("[WINDOW CREATE] window={} parent={} name=\"{}\" hash=#{:016X} len={}",
                         static_cast<void*>(w),
                         static_cast<void*>(parent),
                         nameStr,
                         hash,
                         name ? static_cast<unsigned long long>(name->length) : 0ull);

            return w;
        }

        void __fastcall RegisterUiGraphNodeCtorHook(fox::StrCode32 sig32, fox::UiGraphNodeCtorFn ctor)
        {
            RegisterUiGraphNodeCtor(sig32, ctor);
            spdlog::debug("[REG UI GRAPH NODE] sig32=#{:08X} ctorThunk={}",
                          sig32,
                          static_cast<const void*>(reinterpret_cast<const void*>(ctor)));
        }

        void __fastcall GraphNodeFactoryHook(fox::UiShared* outGraphNode, fox::StrCode32 graphSid)
        {
            GraphNodeFactory(outGraphNode, graphSid);
            // spdlog::debug("[UI GRAPH NODE FACTORY] outGraphNode={} graphSid=#{:08X}",
            //               static_cast<const void*>(outGraphNode),
            //               graphSid);
        }

        fox::StrCode32* __fastcall GetStringIdHook(fox::StrCode* out, const char* string)
        {
            fox::StrCode32* sid = GetStringId(out, string);

            spdlog::debug("[STRING ID] retSid={} out={} string={}", *sid, *out, string);

            return sid;
        }

        void __fastcall CallHudMessageHook(void* commonDataManager, uint32_t msgId)
        {
            spdlog::debug("[CALL HUD MSG] commonDataManager={} msgId={}", commonDataManager, msgId);

            CallHudMessage(commonDataManager, msgId);
        }

        void __fastcall CallHudMessageWithNumberHook(void* commonDataManager /*RCX*/, uint32_t msgId /*EDX*/,
                                                     uint32_t num1 /*R8D*/, uint32_t num2 /*R9D*/)
        {
            spdlog::debug("[CALL HUD NMR] commonDataManager={} msgId={} num1={} num2={}", commonDataManager, msgId,
                          num1, num2);

            CallHudMessageWithNumber(commonDataManager, msgId, num1, num2);
        }

        void __fastcall CallHudMessageWithReceiverHook(void* commonDataManager /*RCX*/, uint32_t msgId /*EDX*/,
                                                       const void* messageArgs /*R8*/,
                                                       uint32_t receiverStrCode32 /*R9D*/)
        {
            spdlog::debug("[CALL HUD RCVR] commonDataManager={} msgId={} messageArgs={} receiverStrCode32={}",
                          commonDataManager, msgId, messageArgs, receiverStrCode32);

            CallHudMessageWithReceiver(commonDataManager, msgId, messageArgs, receiverStrCode32);
        }

        void __fastcall HudCommonCallHudMessageHook(void* hudSystemImpl /*RCX*/, uint32_t msgId /*EDX*/,
                                                    uint32_t arg /*R8D*/, uint32_t receiverStrCode32 /*R9D*/)
        {
            spdlog::debug("[HUD COMMON CALL HUD MSG] hudSystemImpl={} msgId={} arg={} receiverStrCode32={}",
                          hudSystemImpl, msgId, arg, receiverStrCode32);

            HudCommonCallHudMessage(hudSystemImpl, msgId, arg, receiverStrCode32);
        }

        void __fastcall InitializeHudUigDatasHook(void* self)
        {
            spdlog::debug("[INIT HUD UIG] self={}", self);

            InitializeHudUigDatas(self);
        }

        bool __fastcall AnnounceLogViewHook(void* cdm, // RCX: tpp::ui::hud::CommonDataManager*
                                            const char* text, // RDX: zero-terminated message
                                            uint8_t flags, // R8B : bitfield (uses both BL and BPL; 0x10 tested)
                                            uint8_t opts // R9B : aux/route selector
        )
        {
            bool ret = AnnounceLogView(cdm, text, flags, opts);
            spdlog::debug("[ANNC LOG] ret={} cdm={} text={} flags={} opts={}",
                          ret, cdm, text ? text : "", flags, opts);
            return ret;
        }

        void __fastcall SetLayoutActiveHook(void* windowIface, bool enable)
        {
            spdlog::debug("[SLA] windowIface={} enable={}", windowIface, enable);

            return SetLayoutActive(windowIface, enable);
        }

        void __fastcall SetUiModelNodeTranslateHook(void* node, const float* v)
        {
            spdlog::debug("[SET TRANSLATE] node={} v=({}, {}, {}, {})",
                          node, v[0], v[1], v[2], v[3]);

            SetUiModelNodeTranslate(node, v);
        }

        void* __fastcall GetLayoutComponentHook(void* self)
        {
            auto retComponent = GetLayoutComponent(self);
            spdlog::debug("[GetLayoutComponent] self={} ret={}", self, retComponent);
            return retComponent;
        }

        void __fastcall SetupModelHook(void* self)
        {
            SetupModel(self);
            spdlog::debug("[SETUP MODEL] self={}", self);
        }

        bool __fastcall ReadUiModelFileHook(fox::ui::Model* model)
        {
            bool ok = ReadUiModelFile(model);

            void* fileHeader = nullptr;
            if (model)
                fileHeader = *reinterpret_cast<void**>(reinterpret_cast<uint8_t*>(model) + 0x68);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);
                auto& info = g_modelInfo[model];
                info.fileHeader = fileHeader;
                // info.modelName is filled in NewUiModelSharedPtrHook
            }

            spdlog::info("[READ MODEL FILE] ok={} model={} fileHeader={}",
                         ok,
                         static_cast<void*>(model),
                         fileHeader);
            return ok;
        }

        int __fastcall ActSetTextAnalysisHook(fox::ui::ActSetText*   self,
                                                fox::String*           text,
                                                void*         groupA,   // FontGroupInfo*
                                                void*         groupB,   // FONTDATATYPE
                                                void*           dataType, // [rsp+38h]
                                                uint16_t               param5,
                                                float                  param6)
        {
            int retInt = ActSetTextAnalysis(self, text, groupA, groupB, dataType, param5, param6);
            auto base   = reinterpret_cast<uint8_t*>(self);
            auto cstr   = *reinterpret_cast<const char* const*>(base + 0x98);
               spdlog::info("[ACT SET TEXT] self={} text=\"{}\" rawText=\"{}\" vtbl={}",
                 static_cast<void*>(self),
                 FoxStringToStd(text),
                 FoxStringToHex(text),
                 *reinterpret_cast<void* const*>(self));
            
            return retInt;
        }

        void __fastcall ActSetTextHelperHook(fox::ui::ActSetText* self)
        {
            spdlog::info("[ACT SET TEXT] self={}", static_cast<void*>(self));
            ActSetTextHelper(self);
        }

        void __fastcall ReadUiModelNodeHook(fox::ui::ModelNode* self,
                                            fox::ui::ModelFileHeader* fileHeader,
                                            fox::ui::ModelNodeHeader* nodeHeader,
                                            fox::StrCode32* strCode32s,
                                            uint32_t* outName)
        {
            ReadUiModelNode(self, fileHeader, nodeHeader, strCode32s, outName);

            {
                std::lock_guard<std::mutex> lock(g_uiMutex);

                // Find model whose fileHeader matches this one
                for (auto& kv : g_modelInfo)
                {
                    fox::ui::Model* model = kv.first;
                    auto& info = kv.second;

                    if (info.fileHeader == fileHeader)
                    {
                        info.nodes.push_back(self);
                        break; // assume first hit is fine
                    }
                }
            }

            spdlog::debug("[READ MODEL NODE] self={} fileHeader={} nodeHeader={} strCode32s={} outName={}",
                          static_cast<void*>(self),
                          static_cast<void*>(fileHeader),
                          static_cast<void*>(nodeHeader),
                          reinterpret_cast<const void*>(strCode32s),
                          reinterpret_cast<const void*>(outName));
        }

        const char* __fastcall GetManagerTextHook(void* self, fox::StrCode32 sid32)
        {
            auto ret = GetManagerText(self, sid32); // original
            spdlog::debug("[GET MANAGER TEXT] ret={} self={} sid32={}", ret, self, sid32);
            return ret;
        }

        static bool JustPressed(int vk)
        {
            static SHORT prev[256] = {};
            SHORT s = GetAsyncKeyState(vk);
            bool now = (s & 0x8000) != 0;
            bool was = (prev[vk] & 0x8000) != 0;
            prev[vk] = s;
            return now && !was;
        }

        // Phase tick: hotkeys
        void __fastcall UpdatePhaseUiHook(void* phase)
        {
            UpdatePhaseUi(phase);

            // F7: Injection
            if (JustPressed(VK_F7))
            {
                // NOOP
            }

            // View Tree Print
            if (JustPressed(VK_F8))
            {
                spdlog::info("[HK] F8 -> Printing View Tree");
                DumpWindowAndLayoutTree();
            }

            if (JustPressed(VK_F9))
            {
                spdlog::info("[HK] F9 -> Printing Orphan Layout Tree");
                DumpOrphanLayouts();
            }

            if (JustPressed(VK_F10))
            {
                spdlog::info("[HK] F10 -> Printing RAW WindowSlot View Tree");
                DumpWindowSlotViewTreeFromSeenWindows();
            }
        }

        void __fastcall UpdateWindowManagerGraphsHook(fox::ui::WindowManager* self, uint32_t groupId)
        {
            UpdateWindowManagerGraphs(self, groupId);
        }

        // -----------------------------------------------------------------------------
        // Install
        // -----------------------------------------------------------------------------

        void CreateHooks()
        {
            spdlog::set_level(spdlog::level::info);

            CREATE_HOOK(SetTextForModelNodeText)
            CREATE_HOOK(SetTextForModelNodeTextInternal)
            CREATE_HOOK(SetTextUnitsForModelNodeText)
            CREATE_HOOK(SetTextUnits)

            CREATE_HOOK(SetNodeVisibilityWrapper)
            CREATE_HOOK(SetNodeVisibility)
            CREATE_HOOK(IsNodeVisible)

            CREATE_HOOK(NodeConnectShim)
            CREATE_HOOK(NewUiModelText)

            CREATE_HOOK(GetModelWrapper)
            CREATE_HOOK(GetModelNodeFromIndex)

            CREATE_HOOK(GetModelNodeCommon)
            CREATE_HOOK(GetModelNodeCommonInternal)
            CREATE_HOOK(IsHaveModelNodeCommon)

            CREATE_HOOK(OnLayoutComponentDestroy)

            CREATE_HOOK(UpdatePhaseUi)

            // Window route
            CREATE_HOOK(UpdateWindowGraph)
            CREATE_HOOK(AddChildWindow)
            CREATE_HOOK(RemoveChildWindow)
            CREATE_HOOK(CreateNewWindow)
            CREATE_HOOK(GetWindowManager)
            CREATE_HOOK(GetWindowLayout)
            CREATE_HOOK(WindowCtor)
            CREATE_HOOK(WindowDtor)
            CREATE_HOOK(ProcessWindow)
            CREATE_HOOK(FindChildWindow)
            CREATE_HOOK(FindUiWindow)
            CREATE_HOOK(UpdateWindowLayouts)

            CREATE_HOOK(FindWindowFactory)
            // CREATE_HOOK(RegisterWindowFactory) Crashes
            CREATE_HOOK(GetWindowHandle)
            CREATE_HOOK(SetLayoutInfo)
            CREATE_HOOK(GetTextUnits)
            CREATE_HOOK(GetTextUnitsInternal)
            CREATE_HOOK(SetTextUnit)
            CREATE_HOOK(GraphUpdate)
            CREATE_HOOK(GetUixLayout)
            CREATE_HOOK(GetGlobalUixUtility)

            CREATE_HOOK(ConnectLayoutComponent)
            CREATE_HOOK(ConnectLayoutUtilityComponent)
            CREATE_HOOK(ConnectChildWindowToNode)
            CREATE_HOOK(ConnectChildWindowToRoot)
            CREATE_HOOK(ConnectWindowToParent)
            CREATE_HOOK(LayoutConnect)

            CREATE_HOOK(CreateBoxText)
            CREATE_HOOK(DeleteTextUnit)
            CREATE_HOOK(GetConnectModel)

            CREATE_HOOK(SetModelNodeTextDisplayWidth)
            CREATE_HOOK(SetModelNodeTextDisplayHeight)
            CREATE_HOOK(SetModelNodeTextFontSize)
            CREATE_HOOK(SetUixModelNodeTextFontSize)
            CREATE_HOOK(SetModelNodeTextFontSpace)
            CREATE_HOOK(SetModelNodeTextColorRGB)
            CREATE_HOOK(GetModelNodeWorldVisibility)
            CREATE_HOOK(SetModelNodeTextDisplayAreaWidthOffset)
            CREATE_HOOK(ResetModelNodeTextFontSize)
            CREATE_HOOK(ResetModelNodeTextFontSpace)

            CREATE_HOOK(BuildTextAreaPack)
            CREATE_HOOK(ApplyTextAndMeasure)
            CREATE_HOOK(RunAnalysis)

            CREATE_HOOK(WindowCreate)
            // CREATE_HOOK(GetLayoutComponent)
            CREATE_HOOK(GetManagerText)

            CREATE_HOOK(RegisterUiGraphNodeCtor)
            CREATE_HOOK(GraphNodeFactory)
            CREATE_HOOK(GetStringId)

            CREATE_HOOK(CallHudMessage)
            CREATE_HOOK(CallHudMessageWithNumber)
            CREATE_HOOK(CallHudMessageWithReceiver)
            CREATE_HOOK(HudCommonCallHudMessage)
            CREATE_HOOK(InitializeHudUigDatas)

            CREATE_HOOK(AnnounceLogView)
            CREATE_HOOK(SetLayoutActive)
            CREATE_HOOK(SetUiModelNodeTranslate)

            CREATE_HOOK(UpdateWindowManagerGraphs)
            CREATE_HOOK(NewUiLayoutSharedPtr)
            CREATE_HOOK(NewUiModelSharedPtr)
            CREATE_HOOK(UiModelNodeCtor)
            CREATE_HOOK(LayoutCtor)
            CREATE_HOOK(ModelCtor)
            CREATE_HOOK(LayoutDtor)
            CREATE_HOOK(ModelDtor)
            CREATE_HOOK(ModelNodeDtor)
            CREATE_HOOK(LayoutGetLayout)
            CREATE_HOOK(GetWindowInterfaceLayout)

            CREATE_HOOK(SetupModel)
            CREATE_HOOK(ReadUiModelFile)
            CREATE_HOOK(ReadUiModelNode)

            CREATE_HOOK(GetWindowName)
            CREATE_HOOK(CreateChildWindows)
            
            CREATE_HOOK(ActSetTextAnalysis)
            CREATE_HOOK(ActSetTextHelper)

            //-------------------ENABLE-------------------------

            ENABLEHOOK(SetTextForModelNodeText)
            ENABLEHOOK(SetTextForModelNodeTextInternal)
            ENABLEHOOK(SetTextUnitsForModelNodeText)
            ENABLEHOOK(SetTextUnits)

            ENABLEHOOK(SetNodeVisibilityWrapper)
            ENABLEHOOK(SetNodeVisibility)
            ENABLEHOOK(IsNodeVisible)

            ENABLEHOOK(NodeConnectShim)
            ENABLEHOOK(NewUiModelText)

            ENABLEHOOK(GetModelWrapper)
            ENABLEHOOK(GetModelNodeFromIndex)

            ENABLEHOOK(GetModelNodeCommon)
            ENABLEHOOK(GetModelNodeCommonInternal)
            ENABLEHOOK(IsHaveModelNodeCommon)

            ENABLEHOOK(OnLayoutComponentDestroy)

            ENABLEHOOK(UpdatePhaseUi)

            // Window route
            ENABLEHOOK(UpdateWindowGraph)
            ENABLEHOOK(AddChildWindow)
            ENABLEHOOK(RemoveChildWindow)
            ENABLEHOOK(CreateNewWindow)
            ENABLEHOOK(GetWindowManager)
            ENABLEHOOK(GetWindowLayout)
            ENABLEHOOK(WindowCtor)
            ENABLEHOOK(WindowDtor)
            ENABLEHOOK(ProcessWindow)
            ENABLEHOOK(FindChildWindow)
            ENABLEHOOK(FindUiWindow)
            ENABLEHOOK(UpdateWindowLayouts)

            ENABLEHOOK(FindWindowFactory)
            // ENABLEHOOK(RegisterWindowFactory) Crashes
            ENABLEHOOK(GetWindowHandle)
            ENABLEHOOK(SetLayoutInfo)
            ENABLEHOOK(GetTextUnits)
            ENABLEHOOK(GetTextUnitsInternal)
            ENABLEHOOK(SetTextUnit)
            ENABLEHOOK(GraphUpdate)
            ENABLEHOOK(GetUixLayout)
            ENABLEHOOK(GetGlobalUixUtility)

            ENABLEHOOK(ConnectLayoutComponent)
            ENABLEHOOK(ConnectLayoutUtilityComponent)
            ENABLEHOOK(ConnectChildWindowToNode)
            ENABLEHOOK(ConnectChildWindowToRoot)
            ENABLEHOOK(ConnectWindowToParent)
            ENABLEHOOK(LayoutConnect)

            ENABLEHOOK(CreateBoxText)
            ENABLEHOOK(DeleteTextUnit)
            ENABLEHOOK(GetConnectModel)

            ENABLEHOOK(SetModelNodeTextDisplayWidth)
            ENABLEHOOK(SetModelNodeTextDisplayHeight)
            ENABLEHOOK(SetModelNodeTextFontSize)
            ENABLEHOOK(SetUixModelNodeTextFontSize)
            ENABLEHOOK(SetModelNodeTextFontSpace)
            ENABLEHOOK(SetModelNodeTextColorRGB)
            ENABLEHOOK(GetModelNodeWorldVisibility)
            ENABLEHOOK(SetModelNodeTextDisplayAreaWidthOffset)
            ENABLEHOOK(ResetModelNodeTextFontSize)
            ENABLEHOOK(ResetModelNodeTextFontSpace)

            ENABLEHOOK(BuildTextAreaPack)
            ENABLEHOOK(ApplyTextAndMeasure)
            ENABLEHOOK(RunAnalysis)

            ENABLEHOOK(WindowCreate)
            // ENABLEHOOK(GetLayoutComponent)
            ENABLEHOOK(GetManagerText)

            ENABLEHOOK(RegisterUiGraphNodeCtor)
            ENABLEHOOK(GraphNodeFactory)
            ENABLEHOOK(GetStringId)

            ENABLEHOOK(CallHudMessage)
            ENABLEHOOK(CallHudMessageWithNumber)
            ENABLEHOOK(CallHudMessageWithReceiver)
            ENABLEHOOK(HudCommonCallHudMessage)
            ENABLEHOOK(InitializeHudUigDatas)

            ENABLEHOOK(AnnounceLogView)
            ENABLEHOOK(SetLayoutActive)
            ENABLEHOOK(SetUiModelNodeTranslate)

            ENABLEHOOK(UpdateWindowManagerGraphs)
            ENABLEHOOK(NewUiLayoutSharedPtr)
            ENABLEHOOK(NewUiModelSharedPtr)
            ENABLEHOOK(UiModelNodeCtor)
            ENABLEHOOK(LayoutCtor)
            ENABLEHOOK(ModelCtor)
            ENABLEHOOK(LayoutDtor)
            ENABLEHOOK(ModelDtor)
            ENABLEHOOK(ModelNodeDtor)
            ENABLEHOOK(LayoutGetLayout)
            ENABLEHOOK(GetWindowInterfaceLayout)

            ENABLEHOOK(SetupModel)
            ENABLEHOOK(ReadUiModelFile)
            ENABLEHOOK(ReadUiModelNode)

            ENABLEHOOK(GetWindowName)
            ENABLEHOOK(CreateChildWindows)

            ENABLEHOOK(ActSetTextAnalysis)
            ENABLEHOOK(ActSetTextHelper)
        }

        // Optional Lua glue placeholders
        int l_PrintViewTree(lua_State* L) { return 0; }

        int CreateLibs(lua_State* L)
        {
            spdlog::debug(__func__);
            luaL_Reg libFuncs[] = {
                {"PrintViewTree", l_PrintViewTree},
                {NULL, NULL}
            };
            luaI_openlib(L, "IhkUI", libFuncs, 0);
            return 1;
        }
    } // namespace Hooks_Ui
} // namespace IHHook
