#include <cstdint>
#include <cstdlib>
#include <iosfwd>
#include <new>
#include <ostream>
#include <streambuf>

#ifdef _WIN64
#include <Windows.h>
#endif

// ============================================================================
// 1. Estructuras de Datos y Layouts de Memoria
// ============================================================================

/**
 * Interfaz base para objetos con tablas de funciones virtuales (vtable).
 * Facilita el manejo de instancias polimórficas en memoria.
 */
struct IDynamicObject {
    void** vftable;
};

/**
 * Interfaz de fábrica para la gestión centralizada de instancias.
 * El método para obtener la instancia activa reside en el desplazamiento +0x10 de la vtable.
 */
struct IObjectFactory {
    void** vftable;
};

/**
 * Nodo de lista enlazada utilizado para el registro de facetas de localización.
 * Cada nodo contiene un puntero al siguiente elemento y a la faceta registrada.
 */
struct FacetRegistryNode {
    FacetRegistryNode* next;
    void* facet;
};

/**
 * Definición técnica del layout de ios_base bajo el modelo de herencia virtual de MSVC.
 */
struct MSVC_IosBase {
    void** vftable;
};

/**
 * Definición técnica del layout de basic_ostream.
 * Incluye punteros a la vftable y a la tabla de bases virtuales (vbtable).
 */
struct MSVC_BasicOstream {
    void** vftable;
    int* vbtable;
};

// ============================================================================
// 2. Definiciones de Tipos y Estado Global
// ============================================================================

using ScalarDeletingDtor = void (*)(void* instance, int flags);
using GetInstanceFunc = IDynamicObject* (*)(IObjectFactory * factory);

// Instancias globales para la gestión de la aplicación
extern IObjectFactory* g_CoreFactory;
extern FacetRegistryNode* g_FacetRegistryHead;

// Flujo de salida principal (habitualmente asociado a stderr)
extern MSVC_BasicOstream g_GlobalOstream;
extern MSVC_IosBase g_GlobalIosBase;
extern void* g_GlobalFileBuf;

// Flujo de salida secundario (habitualmente asociado a stdout)
extern MSVC_BasicOstream g_SecondaryOstream;
extern MSVC_IosBase g_SecondaryIosBase;
extern void* g_SecondaryFileBuf;

// Control de manejadores de terminación atexit
extern int g_AtexitHandlerIndex;
extern void* g_EncodedAtexitTable;

// Prototipos de funciones externas para la manipulación de recursos del sistema
extern void* OstreamCtor(void* ostreamAddr, void* streamBufAddr, int a2, int a3);
extern void* AcquireStreamHandle(int fileDescriptor);
extern void FilebufClose(void* fileBufAddr);
extern void FilebufOpen(void* fileBufAddr, void* handle, int mode);
extern void CleanupSecondaryFileBuf();
extern void CleanupGlobalFileBuf();
extern void* DecodePointer(void* encoded);

// ============================================================================
// 3. Implementación de la Lógica de Limpieza
// ============================================================================

/**
 * Registra una nueva faceta de localización en la lista global.
 */
void Facet_Register(void* facet)
{
    auto* node = static_cast<FacetRegistryNode*>(::operator new(sizeof(FacetRegistryNode)));
    if (node) {
        node->next = g_FacetRegistryHead;
        node->facet = facet;
    }
    g_FacetRegistryHead = node;
}

/**
 * Recorre y libera todos los recursos asociados al registro de facetas.
 */
void DestroyFacetRegistry()
{
    while (g_FacetRegistryHead) {
        FacetRegistryNode* current = g_FacetRegistryHead;
        g_FacetRegistryHead = current->next;

        if (current->facet) {
            auto getImpl = reinterpret_cast<void* (*)(void*)>(reinterpret_cast<void**>(current->facet)[2]);
            void* instance = getImpl(current->facet);

            if (instance) {
                auto dtor = reinterpret_cast<ScalarDeletingDtor>(reinterpret_cast<void**>(instance)[0]);
                dtor(instance, 1);
            }
        }
        ::operator delete(current);
    }
}

/**
 * Obtiene y destruye la instancia activa gestionada por la fábrica principal.
 */
void CleanupDynamicInstance()
{
    if (!g_CoreFactory)
        return;

    auto getImpl = reinterpret_cast<GetInstanceFunc>(g_CoreFactory->vftable[2]);
    IDynamicObject* instance = getImpl(g_CoreFactory);

    if (instance) {
        auto dtor = reinterpret_cast<ScalarDeletingDtor>(instance->vftable[0]);
        dtor(instance, 1);
    }
}

/**
 * Lee el desplazamiento de la base virtual necesario para la restauración de vtables.
 */
static inline int ReadVbaseOffset(const void* ostreamBase)
{
    return *reinterpret_cast<const int*>(reinterpret_cast<const char*>(ostreamBase) + 4);
}

/**
 * Ejecuta la lógica de destrucción de flujos ostream, restaurando las vtables
 * originales de la biblioteca estándar antes de invocar los destructores base.
 */
void DestroyGlobalOstream()
{
    char* osBase = reinterpret_cast<char*>(&g_GlobalOstream);
    int vbaseOffset = ReadVbaseOffset(osBase);

    void*** vftPtr = reinterpret_cast<void***>(osBase + vbaseOffset);
    *vftPtr = reinterpret_cast<void**>(std::basic_ostream<char>::vftable);

    int* preVb = reinterpret_cast<int*>(osBase - 4 + vbaseOffset);
    *preVb = vbaseOffset - 0x10;

    g_GlobalIosBase.vftable = reinterpret_cast<void**>(std::ios_base::vftable);
    std::ios_base::_Ios_base_dtor(reinterpret_cast<std::ios_base*>(&g_GlobalIosBase));
}

void DestroySecondaryOstream()
{
    char* osBase = reinterpret_cast<char*>(&g_SecondaryOstream);
    int vbaseOffset = ReadVbaseOffset(osBase);

    void*** vftPtr = reinterpret_cast<void***>(osBase + vbaseOffset);
    *vftPtr = reinterpret_cast<void**>(std::basic_ostream<char>::vftable);

    int* preVb = reinterpret_cast<int*>(osBase - 4 + vbaseOffset);
    *preVb = vbaseOffset - 0x10;

    g_SecondaryIosBase.vftable = reinterpret_cast<void**>(std::ios_base::vftable);
    std::ios_base::_Ios_base_dtor(reinterpret_cast<std::ios_base*>(&g_SecondaryIosBase));
}

// ============================================================================
// 4. Inicialización de Recursos y Despacho de atexit
// ============================================================================

void InitSecondaryOstream()
{
    OstreamCtor(&g_SecondaryOstream, &g_SecondaryFileBuf, 0, 1);
    std::atexit(DestroySecondaryOstream);
}

void InitSecondaryFileBuf()
{
    void* handle = AcquireStreamHandle(1);
    FilebufClose(&g_SecondaryFileBuf);
    *reinterpret_cast<void**>(&g_SecondaryFileBuf) = std::basic_filebuf<char>::vftable;
    FilebufOpen(&g_SecondaryFileBuf, handle, 0);
    std::atexit(CleanupSecondaryFileBuf);
}

void InitGlobalOstream()
{
    OstreamCtor(&g_GlobalOstream, &g_GlobalFileBuf, 0, 1);
    std::atexit(DestroyGlobalOstream);
}

void InitGlobalFileBuf()
{
    void* handle = AcquireStreamHandle(2);
    FilebufClose(&g_GlobalFileBuf);
    *reinterpret_cast<void**>(&g_GlobalFileBuf) = std::basic_filebuf<char>::vftable;
    FilebufOpen(&g_GlobalFileBuf, handle, 0);
    std::atexit(CleanupGlobalFileBuf);
}

/**
 * Procesa la tabla de callbacks registrados para la terminación del proceso,
 * decodificando los punteros antes de su ejecución.
 */
void InvokeAtexitHandlers()
{
    while (g_AtexitHandlerIndex < 10) {
        long long slotOffset = static_cast<long long>(g_AtexitHandlerIndex) * 8;
        g_AtexitHandlerIndex++;

        void* encoded = *reinterpret_cast<void**>(
            reinterpret_cast<char*>(g_EncodedAtexitTable) + slotOffset);
        auto callback = static_cast<void (*)()>(DecodePointer(encoded));
        if (callback)
            callback();
    }
}
