#include <sys/stat.h>
#include <iostream>
#include <cstdlib>

#include "binaryninjacore.h"
#include "binaryninjaapi.h"

using namespace BinaryNinja;
using namespace std;

// C++ examples: https://github.com/bambu/binaryninja-api/tree/5a42aec73a77a3a54baf054cde9047533709be31/examples
/*
Goal
	* provide python-accessible APIs written in C++ for speed purposes
*/

#include <libgen.h>
#include <dlfcn.h>
string get_plugins_directory(){
    Dl_info info;
    if (!dladdr((void *)BNGetBundledPluginDirectory, &info))
        return NULL;

    stringstream ss;
    ss << dirname((char *)info.dli_fname) << "/plugins/";
    return ss.str();
}

int main(){
	  /* In order to initiate the bundled plugins properly, the location
	 * of where bundled plugins directory is must be set. Since
	 * libbinaryninjacore is in the path get the path to it and use it to
	 * determine the plugins directory */
	SetBundledPluginDirectory(get_plugins_directory());
	InitCorePlugins();
	InitUserPlugins();

	auto bd = BinaryData(new FileMetadata(), fname);
	BinaryView *bv;

	for (auto type : BinaryViewType::GetViewTypes()) {
	    if (type->IsTypeValidForData(&bd) && type->GetName() != "Raw") {
	        bv = type->Create(&bd);
	        break;
	    }
	}

}
