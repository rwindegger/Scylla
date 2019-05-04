#include "ImportsHandling.h"

#include <atlmisc.h>
#include <atlcrack.h>
#include <multitree.h> // CMultiSelectTreeViewCtrl

#include "resource.h"

#include "Thunks.h"
#include "Architecture.h"
#include "Scylla.h"


void ImportThunk::invalidate()
{
    ordinal = 0;
    hint = 0;
    valid = false;
    suspect = false;
    moduleName[0] = 0;
    name[0] = 0;
}

bool ImportModuleThunk::isValid() const
{
    std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin();
    while (iterator != thunkList.end())
    {
        if (!iterator->second.valid)
        {
            return false;
        }
        iterator++;
    }

    return true;
}

DWORD_PTR ImportModuleThunk::getFirstThunk() const
{
    if (!thunkList.empty())
    {
        const std::map<DWORD_PTR, ImportThunk>::const_iterator iterator = thunkList.begin();
        return iterator->first;
    }
    else
    {
        return 0;
    }
}

ImportsHandling::ImportsHandling(CMultiSelectTreeViewCtrl& TreeImports)
    : numberOfFunctions(0)
    , stringBuffer{}
    , TreeImports(TreeImports)
{
    hIconCheck.LoadIcon(IDI_ICON_CHECK, 16, 16);
    hIconWarning.LoadIcon(IDI_ICON_WARNING, 16, 16);
    hIconError.LoadIcon(IDI_ICON_ERROR, 16, 16);

    CDCHandle dc = CWindow(::GetDesktopWindow()).GetDC();
    const int bits = dc.GetDeviceCaps(BITSPIXEL);

    const UINT FLAGS = bits > 16 ? ILC_COLOR32 : ILC_COLOR24 | ILC_MASK;

    TreeIcons.Create(16, 16, FLAGS, 3, 1);
    TreeIcons.AddIcon(hIconCheck);
    TreeIcons.AddIcon(hIconWarning);
    TreeIcons.AddIcon(hIconError);

    m_thunkCount = m_invalidThunkCount = m_suspectThunkCount = 0;
}

ImportsHandling::~ImportsHandling()
{
    TreeIcons.Destroy();
}

bool ImportsHandling::isModule(const CTreeItem& item)
{
    return nullptr != getModuleThunk(item);
}

bool ImportsHandling::isImport(const CTreeItem& item)
{
    return nullptr != getImportThunk(item);
}

ImportModuleThunk * ImportsHandling::getModuleThunk(CTreeItem item)
{
    std::unordered_map<HTREEITEM, TreeItemData>::const_iterator it = itemData.find(item);
    if (it != itemData.end())
    {
        const TreeItemData * data = &it->second;
        if (data->isModule)
        {
            return data->module;
        }
    }
    return nullptr;
}

ImportThunk * ImportsHandling::getImportThunk(const CTreeItem& item)
{
    TreeItemData * data = getItemData(item);
    if (data && !data->isModule)
    {
        return data->import;
    }
    return nullptr;
}

void ImportsHandling::setItemData(CTreeItem item, const TreeItemData * data)
{
    itemData[item] = *data;
}

ImportsHandling::TreeItemData * ImportsHandling::getItemData(CTreeItem item)
{
    std::unordered_multimap<HTREEITEM, TreeItemData>::iterator it = itemData.find(item);
    if (it != itemData.end())
    {
        return &it->second;
    }
    return nullptr;
}

void ImportsHandling::updateCounts()
{
    m_thunkCount = m_invalidThunkCount = m_suspectThunkCount = 0;

    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        std::map<DWORD_PTR, ImportThunk>::iterator it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            m_thunkCount++;
            if (!importThunk.valid)
                m_invalidThunkCount++;
            else if (importThunk.suspect)
                m_suspectThunkCount++;

            it_import++;
        }

        it_module++;
    }
}

/*bool ImportsHandling::addImport(const WCHAR * moduleName, const CHAR * name, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect)
{
    ImportThunk import;
    ImportModuleThunk  * module = 0;
    std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;

    if (moduleList.size() > 1)
    {
        iterator1 = moduleList.begin();
        while (iterator1 != moduleList.end())
        {
            if (rva >= iterator1->second.firstThunk)
            {
                iterator1++;
                if (iterator1 == moduleList.end())
                {
                    iterator1--;
                    module = &(iterator1->second);
                    break;
                }
                else if (rva < iterator1->second.firstThunk)
                {
                    iterator1--;
                    module = &(iterator1->second);
                    break;
                }
            }
        }
    }
    else
    {
        iterator1 = moduleList.begin();
        module = &(iterator1->second);
    }

    if (!module)
    {
        Scylla::debugLog.log(L"ImportsHandling::addFunction module not found rva " PRINTF_DWORD_PTR_FULL, rva);
        return false;
    }

    //TODO
    import.suspect = true;
    import.valid = false;
    import.va = va;
    import.rva = rva;
    import.ordinal = ordinal;

    wcscpy_s(import.moduleName, MAX_PATH, moduleName);
    strcpy_s(import.name, MAX_PATH, name);

    module->thunkList.insert(std::pair<DWORD_PTR,ImportThunk>(import.rva, import));

    return true;
}
*/

/*
bool ImportsHandling::addModule(const WCHAR * moduleName, DWORD_PTR firstThunk)
{
    ImportModuleThunk module;

    module.firstThunk = firstThunk;
    wcscpy_s(module.moduleName, MAX_PATH, moduleName);

    moduleList.insert(std::pair<DWORD_PTR,ImportModuleThunk>(firstThunk,module));

    return true;
}
*/

void ImportsHandling::displayAllImports()
{
    TreeImports.DeleteAllItems();
    itemData.clear();
    TreeImports.SetImageList(TreeIcons);

    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        moduleThunk.key = moduleThunk.firstThunk; // This belongs elsewhere...
        moduleThunk.hTreeItem = addDllToTreeView(TreeImports, &moduleThunk);

        std::map<DWORD_PTR, ImportThunk>::iterator it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            importThunk.key = importThunk.rva; // This belongs elsewhere...
            importThunk.hTreeItem = addApiToTreeView(TreeImports, moduleThunk.hTreeItem, &importThunk);

            it_import++;
        }

        it_module++;
    }

    updateCounts();
}

void ImportsHandling::clearAllImports()
{
    TreeImports.DeleteAllItems();
    itemData.clear();
    moduleList.clear();
    updateCounts();
}

CTreeItem ImportsHandling::addDllToTreeView(CMultiSelectTreeViewCtrl& idTreeView, ImportModuleThunk * moduleThunk)
{
    CTreeItem item = idTreeView.InsertItem(TEXT(""), nullptr, TVI_ROOT);

    item.SetData(itemData.size());

    TreeItemData data;
    data.isModule = true;
    data.module = moduleThunk;

    setItemData(item, &data);

    updateModuleInTreeView(moduleThunk, item);
    return item;
}

CTreeItem ImportsHandling::addApiToTreeView(CMultiSelectTreeViewCtrl& idTreeView, CTreeItem parentDll, ImportThunk * importThunk)
{
    CTreeItem item = idTreeView.InsertItem(TEXT(""), parentDll, TVI_LAST);

    item.SetData(itemData.size());

    TreeItemData data;
    data.isModule = false;
    data.import = importThunk;

    setItemData(item, &data);

    updateImportInTreeView(importThunk, item);
    return item;
}

void ImportsHandling::selectImports(bool invalid, bool suspect)
{
    TreeImports.SelectAllItems(FALSE); //remove selection

    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        std::map<DWORD_PTR, ImportThunk>::iterator it_import = moduleThunk.thunkList.begin();
        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            if (invalid && !importThunk.valid || suspect && importThunk.suspect)
            {
                TreeImports.SelectItem(importThunk.hTreeItem, TRUE);
                importThunk.hTreeItem.EnsureVisible();
            }

            it_import++;
        }

        it_module++;
    }
}

bool ImportsHandling::invalidateImport(const CTreeItem& item)
{
    ImportThunk * import = getImportThunk(item);
    if (import)
    {
        CTreeItem parent = item.GetParent();
        if (!parent.IsNull())
        {
            const ImportModuleThunk * module = getModuleThunk(parent);
            if (module)
            {
                import->invalidate();

                updateImportInTreeView(import, import->hTreeItem);
                updateModuleInTreeView(module, module->hTreeItem);

                updateCounts();
                return true;
            }
        }
    }
    return false;
}

bool ImportsHandling::invalidateModule(const CTreeItem& item)
{
    ImportModuleThunk * module = getModuleThunk(item);
    if (module)
    {
        std::map<DWORD_PTR, ImportThunk>::iterator it_import = module->thunkList.begin();
        while (it_import != module->thunkList.end())
        {
            ImportThunk * import = &it_import->second;
            import->invalidate();
            updateImportInTreeView(import, import->hTreeItem);
            it_import++;
        }

        updateModuleInTreeView(module, module->hTreeItem);

        updateCounts();
        return true;
    }
    return false;
}

bool ImportsHandling::setImport(const CTreeItem& item, LPCTSTR moduleName, LPCTSTR apiName, WORD ordinal, WORD hint, bool valid, bool suspect)
{
    ImportThunk * import = getImportThunk(item);
    if (import)
    {
        CTreeItem parent = item.GetParent();
        if (!parent.IsNull())
        {
            ImportModuleThunk * module = getModuleThunk(parent);
            if (module)
            {

                _tcscpy_s(import->moduleName, moduleName);
                _tcscpy_s(import->name, apiName);
                import->ordinal = ordinal;
                //import->apiAddressVA = api->va; //??
                import->hint = hint;
                import->valid = valid;
                import->suspect = suspect;

                if (module->isValid())
                {
                    scanAndFixModuleList();
                    displayAllImports();
                }
                else
                {
                    updateImportInTreeView(import, item);
                    updateCounts();
                }
                return true;
            }
        }
    }
    return false;
}

void ImportsHandling::updateImportInTreeView(const ImportThunk * importThunk, CTreeItem item)
{
    if (importThunk->valid)
    {
        TCHAR tempString[300];

        if (importThunk->name[0] != 0x00)
        {
            _stprintf_s(tempString, TEXT("ord: %04X name: %s"), importThunk->ordinal, importThunk->name);
        }
        else
        {
            _stprintf_s(tempString, TEXT("ord: %04X"), importThunk->ordinal);
        }

        _stprintf_s(stringBuffer, TEXT(" rva: ") PRINTF_DWORD_PTR_HALF TEXT(" mod: %s %s"), importThunk->rva, importThunk->moduleName, tempString);
    }
    else
    {
        _stprintf_s(stringBuffer, TEXT(" rva: ") PRINTF_DWORD_PTR_HALF TEXT(" ptr: ") PRINTF_DWORD_PTR_FULL, importThunk->rva, importThunk->apiAddressVA);
    }

    item.SetText(stringBuffer);
    const Icon icon = getAppropiateIcon(importThunk);
    item.SetImage(icon, icon);
}

void ImportsHandling::updateModuleInTreeView(const ImportModuleThunk * importThunk, CTreeItem item)
{
    _stprintf_s(stringBuffer, TEXT("%s (%zd) FThunk: ") PRINTF_DWORD_PTR_HALF, importThunk->moduleName, importThunk->thunkList.size(), importThunk->firstThunk);

    item.SetText(stringBuffer);
    const Icon icon = getAppropiateIcon(importThunk->isValid());
    item.SetImage(icon, icon);
}

ImportsHandling::Icon ImportsHandling::getAppropiateIcon(const ImportThunk * importThunk)
{
    if (importThunk->valid)
    {
        if (importThunk->suspect)
        {
            return iconWarning;
        }
        else
        {
            return iconCheck;
        }
    }
    else
    {
        return iconError;
    }
}

ImportsHandling::Icon ImportsHandling::getAppropiateIcon(bool valid)
{
    if (valid)
    {
        return iconCheck;
    }
    else
    {
        return iconError;
    }
}

bool ImportsHandling::cutImport(CTreeItem item)
{
    ImportThunk * import = getImportThunk(item);
    if (import)
    {
        CTreeItem parent = item.GetParent();
        if (!parent.IsNull())
        {
            ImportModuleThunk * module = getModuleThunk(parent);
            if (module)
            {
                itemData.erase(item);
                import->hTreeItem.Delete();
                module->thunkList.erase(import->key);
                import = nullptr;

                if (module->thunkList.empty())
                {
                    itemData.erase(parent);
                    module->hTreeItem.Delete();
                    moduleList.erase(module->key);
                    module = nullptr;
                }
                else
                {
                    if (module->isValid() && module->moduleName[0] == TEXT('?'))
                    {
                        //update module name
                        _tcscpy_s(module->moduleName, module->thunkList.begin()->second.moduleName);
                    }

                    module->firstThunk = module->thunkList.begin()->second.rva;
                    updateModuleInTreeView(module, module->hTreeItem);
                }

                updateCounts();
                return true;
            }
        }
    }
    return false;
}

bool ImportsHandling::cutModule(CTreeItem item)
{
    ImportModuleThunk * module = getModuleThunk(item);
    if (module)
    {
        CTreeItem child = item.GetChild();
        while (!child.IsNull())
        {
            itemData.erase(child);
            child = child.GetNextSibling();
        }
        itemData.erase(item);
        module->hTreeItem.Delete();
        moduleList.erase(module->key);
        module = nullptr;
        updateCounts();
        return true;
    }
    return false;
}

DWORD_PTR ImportsHandling::getApiAddressByNode(const CTreeItem& item)
{
    const ImportThunk * import = getImportThunk(item);
    if (import)
    {
        return import->apiAddressVA;
    }
    return 0;
}

void ImportsHandling::scanAndFixModuleList()
{
    TCHAR prevModuleName[MAX_PATH] = { 0 };

    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        std::map<DWORD_PTR, ImportThunk>::iterator it_import = moduleThunk.thunkList.begin();

        while (it_import != moduleThunk.thunkList.end())
        {
            ImportThunk &importThunk = it_import->second;

            if (importThunk.moduleName[0] == 0 || importThunk.moduleName[0] == L'?')
            {
                addNotFoundApiToModuleList(&importThunk);
            }
            else
            {

                if (_tcsicmp(importThunk.moduleName, prevModuleName) != 0)
                {
                    addModuleToModuleList(importThunk.moduleName, importThunk.rva);
                }

                addFunctionToModuleList(&importThunk);
            }

            if (_tcslen(importThunk.moduleName) < MAX_PATH)
                _tcscpy_s(prevModuleName, importThunk.moduleName);
            it_import++;
        }

        moduleThunk.thunkList.clear();

        it_module++;
    }

    moduleList = moduleListNew;
    moduleListNew.clear();
}

bool ImportsHandling::findNewModules(std::map<DWORD_PTR, ImportThunk> & thunkList)
{
    throw std::exception("The method or operation is not implemented.");
}

bool ImportsHandling::addModuleToModuleList(LPCTSTR moduleName, DWORD_PTR firstThunk)
{
    ImportModuleThunk module;

    module.firstThunk = firstThunk;
    if (_tcslen(moduleName) < MAX_PATH)
        _tcscpy_s(module.moduleName, moduleName);

    module.key = module.firstThunk;
    moduleListNew[module.key] = module;
    return true;
}

bool ImportsHandling::isNewModule(LPCTSTR moduleName)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module = moduleListNew.begin();
    while (it_module != moduleListNew.end())
    {
        if (!_tcsicmp(it_module->second.moduleName, moduleName))
        {
            return false;
        }

        it_module++;
    }

    return true;
}

void ImportsHandling::addUnknownModuleToModuleList(DWORD_PTR firstThunk)
{
    ImportModuleThunk module;

    module.firstThunk = firstThunk;
    _tcscpy_s(module.moduleName, TEXT("?"));

    module.key = module.firstThunk;
    moduleListNew[module.key] = module;
}

bool ImportsHandling::addNotFoundApiToModuleList(const ImportThunk * apiNotFound)
{
    ImportThunk import;
    ImportModuleThunk  * module = nullptr;
    DWORD_PTR rva = apiNotFound->rva;

    if (moduleListNew.size() > 0)
    {
        std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module = moduleListNew.begin();
        while (it_module != moduleListNew.end())
        {
            if (rva >= it_module->second.firstThunk)
            {
                it_module++;
                if (it_module == moduleListNew.end())
                {
                    it_module--;
                    //new unknown module
                    if (it_module->second.moduleName[0] == L'?')
                    {
                        module = &(it_module->second);
                    }
                    else
                    {
                        addUnknownModuleToModuleList(apiNotFound->rva);
                        module = &(moduleListNew.find(rva)->second);
                    }

                    break;
                }
                else if (rva < it_module->second.firstThunk)
                {
                    it_module--;
                    module = &(it_module->second);
                    break;
                }
            }
            else
            {
                Scylla::debugLog.log(TEXT("Error iterator1 != (*moduleThunkList).end()"));
                break;
            }
        }
    }
    else
    {
        //new unknown module
        addUnknownModuleToModuleList(apiNotFound->rva);
        module = &(moduleListNew.find(rva)->second);
    }

    if (!module)
    {
        Scylla::debugLog.log(TEXT("ImportsHandling::addFunction module not found rva ") PRINTF_DWORD_PTR_FULL, rva);
        return false;
    }


    import.suspect = true;
    import.valid = false;
    import.va = apiNotFound->va;
    import.rva = apiNotFound->rva;
    import.apiAddressVA = apiNotFound->apiAddressVA;
    import.ordinal = 0;

    _tcscpy_s(import.moduleName, TEXT("?"));
    _tcscpy_s(import.name, TEXT("?"));

    import.key = import.rva;
    module->thunkList[import.key] = import;
    return true;
}

bool ImportsHandling::addFunctionToModuleList(const ImportThunk * apiFound)
{
    ImportThunk import;
    ImportModuleThunk  * module = nullptr;
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module;

    if (moduleListNew.size() > 1)
    {
        it_module = moduleListNew.begin();
        while (it_module != moduleListNew.end())
        {
            if (apiFound->rva >= it_module->second.firstThunk)
            {
                it_module++;
                if (it_module == moduleListNew.end())
                {
                    it_module--;
                    module = &(it_module->second);
                    break;
                }
                else if (apiFound->rva < it_module->second.firstThunk)
                {
                    it_module--;
                    module = &(it_module->second);
                    break;
                }
            }
            else
            {
                Scylla::debugLog.log(TEXT("Error iterator1 != moduleListNew.end()"));
                break;
            }
        }
    }
    else
    {
        it_module = moduleListNew.begin();
        module = &(it_module->second);
    }

    if (!module)
    {
        Scylla::debugLog.log(TEXT("ImportsHandling::addFunction module not found rva ") PRINTF_DWORD_PTR_FULL, apiFound->rva);
        return false;
    }

    import.suspect = apiFound->suspect;
    import.valid = apiFound->valid;
    import.va = apiFound->va;
    import.rva = apiFound->rva;
    import.apiAddressVA = apiFound->apiAddressVA;
    import.ordinal = apiFound->ordinal;
    import.hint = apiFound->hint;

    if (_tcslen(apiFound->moduleName) < MAX_PATH)
        _tcscpy_s(import.moduleName, apiFound->moduleName);
    _tcscpy_s(import.name, apiFound->name);

    import.key = import.rva;
    module->thunkList[import.key] = import;
    return true;
}

void ImportsHandling::expandAllTreeNodes()
{
    changeExpandStateOfTreeNodes(TVE_EXPAND);
}

void ImportsHandling::collapseAllTreeNodes()
{
    changeExpandStateOfTreeNodes(TVE_COLLAPSE);
}

void ImportsHandling::changeExpandStateOfTreeNodes(UINT flag)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator it_module = moduleList.begin();
    while (it_module != moduleList.end())
    {
        ImportModuleThunk &moduleThunk = it_module->second;

        moduleThunk.hTreeItem.Expand(flag);

        it_module++;
    }
}
