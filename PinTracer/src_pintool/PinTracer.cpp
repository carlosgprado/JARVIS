//
//  This program will trace execution and log to a file.
//  Takes advantage of INTEL Pin's intelligence.
//  It doesn't need to know in advance the functions but
//  is capable to detect when a CALL is executed instead :)
//

#include <stdio.h>
#include <iostream>
#include <fstream>
#include <map>			// used for... maps:)
#include <algorithm>	// used for find()
#include <string.h>		// used for strncmp()
#include <ctype.h>		// used for isupper(), etc.
#include <jansson.h>	// JSON output
#include "pin.H"

using namespace std;
using std::vector;
using std::find;

// Global variables
struct moduledata_t
{
	BOOL excluded;
	ADDRINT begin;
	ADDRINT end;
};

// Module information is saved here
typedef std::map<string, moduledata_t> modmap_t;

std::ofstream LogFile;
std::ofstream JsonFile;
vector<ADDRINT> loggedAddresses;
modmap_t mod_data;
PIN_LOCK lock;

// JSON stuff
json_t* root;
json_t* call_array;
json_t* module_array;

// Command Line stuff
KNOB<BOOL> KnobLogBB(KNOB_MODE_WRITEONCE, "pintool", "bb", "0", "log all basic blocks");
KNOB<BOOL> KnobLogHit(KNOB_MODE_WRITEONCE, "pintool", "hit", "1", "log each function only once");
KNOB<BOOL> KnobLogMainImage(KNOB_MODE_WRITEONCE, "pintool", "main", "1", "log main image functions");
KNOB<string> KnobLogModule(KNOB_MODE_WRITEONCE, "pintool", "only", "None", "log only this module");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.json", "specify trace file name");

////////////////////////////////
// AUXILIARY functions
////////////////////////////////

/**
Very cheap "convert to lowercase"
Since it is not possible to overwrite a
string literal it returns a pointer to
another string
*/
char* c2lc(const char *s)
{
	char* sc = NULL;
	char* p = NULL;

	sc = _strdup(s);
	if (!sc)
		return sc;
	else
		p = sc;

	for (; *s; ++s)
	{
		if (isupper(*s))
			*p = tolower(*s);
		else
			*p = *s;
		++p;
	}

	return sc;
}


/**
Appends an element to the module array.
Example:
append_module(module_array, "kernel32.dll", 0x1000, 0x1FFF, true);
*/
void append_module(json_t* array, char* name, unsigned int begin, unsigned int end, bool excluded)
{
	json_t* module_e = json_object();

	json_object_set_new(module_e, "name", json_string(name));
	json_object_set_new(module_e, "begin", json_integer(begin));
	json_object_set_new(module_e, "end", json_integer(end));

	// Set to true or false
	if (excluded)
		json_object_set_new(module_e, "excluded", json_true());
	else
		json_object_set_new(module_e, "excluded", json_false());

	json_array_append(array, module_e);
}

/**
Appends an element to the call array.
Example:
append_call(call_array, 0, 0x123, 0xABC, false);
*/
void append_call(json_t* array, unsigned short tid, unsigned int u, unsigned int v, bool indirect)
{
	json_t* call_e = json_object();

	json_object_set_new(call_e, "tid", json_integer(tid));
	json_object_set_new(call_e, "u", json_integer(u));
	json_object_set_new(call_e, "v", json_integer(v));

	// Set to true or false
	if (indirect)
		json_object_set_new(call_e, "indirect", json_true());
	else
		json_object_set_new(call_e, "indirect", json_false());

	json_array_append(array, call_e);
}

const char* StripPath(const char *path)
{
	const char *file = strrchr(path, '\\');	// backward slash (for windows paths)

	if (file)
		return file + 1;
	else
		return path;
}


BOOL withinExcludedModules(ADDRINT ip)
{
	for (modmap_t::iterator it = mod_data.begin(); it != mod_data.end(); ++it)
	{
		// If the module is included, no need to check anything
		if (it->second.excluded == FALSE) continue;

		// Is the [E|R]IP value within the range of any excluded module?
		if (ip >= it->second.begin && ip <= it->second.end) return TRUE;
	}

	return FALSE;
}


BOOL alreadyLoggedAddresses(ADDRINT ip)
{
	// TODO: This has to be terribly slow since loggedAddresses is a vector (list)
	// Is this O(n)?
	if (find(loggedAddresses.begin(), loggedAddresses.end(), ip) != loggedAddresses.end())
	{
		// item IS in vector
		return true;
	}
	else
	{
		// item is NOT in vector. Push it for the next time.
		loggedAddresses.push_back(ip);
		return false;
	}
}

// Finish and cleanup functions
void Fini(INT32 code, void *v)
{
	// write JSON dump
	char* json_dump = json_dumps(root, JSON_ENCODE_ANY);
	JsonFile.write(json_dump, strlen(json_dump));
	JsonFile.close();

	// Close log file
	LogFile << endl << "---------------- End of trace ----------------" << endl;
	LogFile.close();
	cout << endl << "[*] Log File closed" << endl;
}

// This is called every time a MODULE (dll, etc.) is LOADED
// Analysis function (execution time)
void imageLoad_cb(IMG Img, void *v)
{
	const char* imageName = IMG_Name(Img).c_str();
	bool excluded = false;
	ADDRINT lowAddress = IMG_LowAddress(Img);
	ADDRINT highAddress = IMG_HighAddress(Img);

	if (IMG_IsMainExecutable(Img) && KnobLogMainImage.Value())
		LogFile << "[-] Analysing main image: " << StripPath(IMG_Name(Img).c_str()) << endl;
	else
		LogFile << "[-] Loaded module:\t" << imageName << endl;

	if (strncmp(KnobLogModule.Value().c_str(), "None", 4) == 0)
	{
		// No option -only was given, normal exclusions are used instead
		if (strncmp(c2lc(imageName), "c:\\windows", 10) == 0)
		{
			// Filter out system dlls
			LogFile << "[!] Filtered " << imageName << endl;
			// I'm not interested on code within these modules
			excluded = true;
			mod_data[imageName].excluded = TRUE;
			mod_data[imageName].begin = lowAddress;
			mod_data[imageName].end = highAddress;
		}
	}
	else {
		const char* pathToProblemDll = KnobLogModule.Value().c_str();

		// Switch everything to lowercase before string comparison
		if (strncmp(c2lc(imageName), c2lc(pathToProblemDll), strlen(pathToProblemDll)) != 0)
		{
			// Filter out everything except the -only parameter
			LogFile << "[!] Filtered " << imageName << endl;
			// I'm not interested on code within these modules
			excluded = true;
			mod_data[imageName].excluded = TRUE;
			mod_data[imageName].begin = lowAddress;
			mod_data[imageName].end = highAddress;
		}
	}

	append_module(module_array, (char*)imageName, lowAddress, highAddress, excluded);

	LogFile << "[-] Module base:\t" << hex << lowAddress << endl;
	LogFile << "[-] Module end:\t" << hex << highAddress << endl;
}

// Log some information related to THREAD execution
void threadStart_cb(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	PIN_GetLock(&lock, threadIndex + 1);
	LogFile << "[*] THREAD 0x" << hex << threadIndex << " STARTED. Flags: " << flags << endl;
	PIN_ReleaseLock(&lock);
}


void threadFinish_cb(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	PIN_GetLock(&lock, threadIndex + 1);
	LogFile << "[*] THREAD 0x" << hex << threadIndex << " FINISHED. Code: " << dec << code << endl;
	PIN_ReleaseLock(&lock);
}


// Log the basic block we are in (within a function)
void LogBasicBlock(ADDRINT ip)
{
	// TODO: Maybe inefficient here
	if (withinExcludedModules(ip))
		return;

	LogFile << "  loc_" << hex << ip << ":" << endl;
}


// CALLBACKS implementing the actual LOGGING
void LogCall(ADDRINT ip, ADDRINT target, THREADID tid, BOOL indirect)
{
	//
	// The format is basically:
	// [THREAD ID] Address of Call -> Address being called
	//

	/* -hit switch present: log only once (hit) */
	if (KnobLogHit.Value() && alreadyLoggedAddresses(target))
		return;

	if (withinExcludedModules(target))
		return;

	append_call(call_array, tid, ip, target, indirect);
}


void LogIndirectCall(ADDRINT ip, ADDRINT target, THREADID tid, BOOL taken)
{
	//
	// This is just a simple wrapper
	//

	if (!taken)
		return;

	LogCall(ip, target, tid, TRUE);
}


//
// This identifies different types of CALL methods
//  and its callbacks log the functions hit
//  NOTE: These are all instrumentation functions (JIT),
//  they just point to the analysis ones
//
void Trace(TRACE trace, void *v)
{
	const BOOL log_bb = KnobLogBB.Value();

	// Iterate through basic blocks
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		// Instrument at basic block level?
		if (log_bb)
		{
			// instrument BBL_InsHead to write "loc_XXXXX",
			// the way IDA Pro does
			INS head = BBL_InsHead(bbl);
			INS_InsertCall(head,
				IPOINT_BEFORE,
				AFUNPTR(LogBasicBlock),		// Analysis function
				IARG_INST_PTR, 				// Current [R|E]IP
				IARG_END);					// No more args
		}

		// Code to instrument the events at the end of a BBL (execution transfer)
		// Checking for calls, etc.
		// NOTE: This is not a BB like shown in IDA but following the definition :)
		INS tail = BBL_InsTail(bbl);


		if (INS_IsDirectBranchOrCall(tail) && !INS_HasFallThrough(tail))
		{
			// DIRECT CALLS: target address is [E|R]IP + offset or an immediate
			// Ex: call 0xDEADFACE
			const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);

			INS_InsertPredicatedCall(
				tail,
				IPOINT_BEFORE,
				AFUNPTR(LogCall),		// Analysis function
				IARG_INST_PTR,			// Caller
				IARG_ADDRINT,			// target's type
				target,					// The XXX in "CALL XXX" :)
				IARG_THREAD_ID,			// Thread ID (different from OS)
				IARG_BOOL,				// Boolean argument
				FALSE,					// False (no indirect call)
				IARG_END				// No more args
				);
		}
		else if (INS_IsCall(tail))
		{
			// INDIRECT CALLS
			// Ex: call EDX, call dword ptr [ebp+0x8], call dword ptr [0x69e6079c]
			INS_InsertCall(
				tail,
				IPOINT_BEFORE,
				AFUNPTR(LogIndirectCall),	// Analysis function
				IARG_INST_PTR,				// Caller
				IARG_BRANCH_TARGET_ADDR,	// Well... target address? :)
				IARG_THREAD_ID,				// Thread ID (different from OS)
				IARG_BRANCH_TAKEN,			// Non zero if branch is taken
				IARG_END					// No more args
				);

		}
	} // end "for(BBL bbl..."
} // end "void Trace..."


// Help message
INT32 Usage()
{
	cout << "--------------------------------------------------------------------------------------" << endl;
	cout << "The awesome PinTracer :)" << endl;
	cout << "Log addresses of every call ever made. Used in differential debugging." << endl;
	cout << "It records information regarding dynamic calls as well!" << endl;
	cout << "--------------------------------------------------------------------------------------" << endl;

	cout << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}


/* Main function - initialize and set instrumentation callbacks */
int main(int argc, char *argv[])
{
	/* Initialize Pin with symbol capabilities */
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) return Usage();

	JsonFile.open(KnobOutputFile.Value().c_str());
	LogFile.open("trace_modules.log");

	LogFile << hex;
	LogFile.setf(ios::showbase);

	string trace_header = string("#\n"
		"# Function Trace | Record of loaded modules\n"
		"# Generated By PinTracer\n"
		"#\n\n");

	LogFile.write(trace_header.c_str(), trace_header.size());

	/* JSON initialization */
	root = json_object();
	call_array = json_array();
	module_array = json_array();
	json_object_set_new(root, "calls", call_array);
	json_object_set_new(root, "modules", module_array);

	/* Instrumentation */
	TRACE_AddInstrumentFunction(Trace, 0);				// Basic Block analysis
	IMG_AddInstrumentFunction(imageLoad_cb, 0);			// Image activities
	PIN_AddThreadStartFunction(threadStart_cb, 0);		// Thread start
	PIN_AddThreadFiniFunction(threadFinish_cb, 0);		// Thread end

	PIN_AddFiniFunction(Fini, 0);

	/* It never returns, sad :) */
	PIN_StartProgram();

	return 0;
}
