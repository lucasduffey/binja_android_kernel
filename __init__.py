#!/usr/bin/env python
# -*- coding: utf-8 -*-
# original author: nforest@k33nteam.org

import os
import re
import sys
import time
import struct

from binaryninja import *

#////////////////////////////////////////////////////////////////////////////////////////////

kallsyms = {
			'arch'		  :32,
			'_start'		:0,
			'numsyms'		:0,
			'address'	   :[],
			'type'		  :[],
			'name'		  :[],
			'address_table'	 : 0,
			'name_table'		: 0,
			'type_table'		: 0,
			'token_table'	   : 0,
			'table_index_table' : 0,
			}

class AndroidKernelView(BinaryView):
	name = "Android Kernel"
	long_name = "Android Kernel"

	def __init__(self, data):
		BinaryView.__init__(self, parent_view = data, file_metadata = data.file)
		self.raw = data

	# OK for now...
	@classmethod
	def is_valid_for_data(self, data):
		hdr = data.read(0, 0x200)

		# find aarch64 magic value
		if re.search('ARMd', hdr):
			return True

		# currently not supporting anything else...
		return False

	def init(self):
		# set 0 as entry_point for now...
		self.add_entry_point(Architecture['aarch64'].standalone_platform, 0)

		# TODO: add other stuff...
		# self.add_function(Architecture['aarch64'].standalone_platform, 0)

		'''
		try:
			hdr = self.raw.read(0, 16)
			self.rom_banks = struct.unpack("B", hdr[4])[0]
			self.vrom_banks = struct.unpack("B", hdr[5])[0]
			self.rom_flags = struct.unpack("B", hdr[6])[0]
			self.mapper_index = struct.unpack("B", hdr[7])[0] | (self.rom_flags >> 4)
			self.ram_banks = struct.unpack("B", hdr[8])[0]
			self.rom_offset = 16
			if self.rom_flags & 4:
				self.rom_offset += 512
			self.rom_length = self.rom_banks * 0x4000

			nmi = struct.unpack("<H", self.read(0xfffa, 2))[0]
			start = struct.unpack("<H", self.read(0xfffc, 2))[0]
			irq = struct.unpack("<H", self.read(0xfffe, 2))[0]
			self.define_auto_symbol(Symbol(FunctionSymbol, nmi, "_nmi"))
			self.define_auto_symbol(Symbol(FunctionSymbol, start, "_start"))
			self.define_auto_symbol(Symbol(FunctionSymbol, irq, "_irq"))
			self.add_function(Architecture['6502'].standalone_platform, nmi)
			self.add_function(Architecture['6502'].standalone_platform, irq)
			self.add_entry_point(Architecture['6502'].standalone_platform, start)

			# Hardware registers
			self.define_auto_symbol(Symbol(DataSymbol, 0x2000, "PPUCTRL"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x2001, "PPUMASK"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x2002, "PPUSTATUS"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x2003, "OAMADDR"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x2004, "OAMDATA"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x2005, "PPUSCROLL"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x2006, "PPUADDR"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x2007, "PPUDATA"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4000, "SQ1_VOL"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4001, "SQ1_SWEEP"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4002, "SQ1_LO"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4003, "SQ1_HI"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4004, "SQ2_VOL"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4005, "SQ2_SWEEP"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4006, "SQ2_LO"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4007, "SQ2_HI"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4008, "TRI_LINEAR"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x400a, "TRI_LO"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x400b, "TRI_HI"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x400c, "NOISE_VOL"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x400e, "NOISE_LO"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x400f, "NOISE_HI"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4010, "DMC_FREQ"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4011, "DMC_RAW"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4012, "DMC_START"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4013, "DMC_LEN"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4014, "OAMDMA"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4015, "SND_CHN"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4016, "JOY1"))
			self.define_auto_symbol(Symbol(DataSymbol, 0x4017, "JOY2"))

			sym_files = [self.raw.file.filename + ".%x.nl" % self.__class__.bank,
					self.raw.file.filename + ".ram.nl",
					self.raw.file.filename + ".%x.nl" % (self.rom_banks - 1)]
			for f in sym_files:
				if os.path.exists(f):
					sym_contents = open(f, "r").read()
					lines = sym_contents.split('\n')
					for line in lines:
						sym = line.split('#')
						if len(sym) < 3:
							break
						addr = int(sym[0][1:], 16)
						name = sym[1]
						self.define_auto_symbol(Symbol(FunctionSymbol, addr, name))
						if addr >= 0x8000:
							self.add_function(Architecture['6502'].standalone_platform, addr)

			return True
		except:
			log_error(traceback.format_exc())
			return False
		'''
		return True

	#def perform_is_valid_offset(self, addr):
	#	if (addr >= 0x8000) and (addr < 0x10000):
	#		return True
	#	return False

	# very important
	def perform_read(self, addr, length):
		# XXX: does rebase effect this??
		return self.raw.read(addr, length)

	#def perform_write(self, addr, value):
	#	return False

	#def perform_get_start(self):
	#	return 0

	#def perform_get_length(self):
	#	return 0x10000

	def perform_is_executable(self):
		return True

	#def perform_get_entry_point(self):
		# XXX: does rebase effect this??
	#	return 0

class AndroidKernelViewBank(AndroidKernelView):
	name = "Android kernel"
	long_name = "Android kernel"

	def __init__(self, data):
		AndroidKernelView.__init__(self, data)

AndroidKernelViewBank.register()

# OK AFAIK
def INT(offset, vmlinux):
	bytes = kallsyms['arch'] / 8
	s = vmlinux[offset:offset+bytes]
	f = 'I' if bytes==4 else 'Q'
	(num,) = struct.unpack(f, s)
	return num

# OK AFAIK
def INT32(offset, vmlinux):
	s = vmlinux[offset:offset+4]
	(num,) = struct.unpack('I', s)
	return num

# OK AFAIK
def INT64(offset, vmlinux):
	s = vmlinux[offset:offset+8]
	(num,) = struct.unpack('Q', s)
	return num

# OK AFAIK
def SHORT(offset, vmlinux):
	s = vmlinux[offset:offset+2]
	(num,) = struct.unpack('H', s)
	return num

# XXX??
def STRIPZERO(offset, vmlinux, step=4):
	NOTZERO = INT32 if step==4 else INT
	for i in xrange(offset,len(vmlinux),step):
		if NOTZERO(i, vmlinux):
			return i

#//////////////////////
# OK AFAIK
def do_token_index_table(kallsyms , offset, vmlinux):
	kallsyms['token_index_table'] = offset
	print '[+] kallsyms_token_index_table = ', hex(offset)

def do_token_table(kallsyms, offset, vmlinux):
	kallsyms['token_table'] = offset
	print '[+] kallsyms_token_table = ', hex(offset)

	for i in xrange(offset,len(vmlinux)):
		if SHORT(i,vmlinux) == 0:
			break
	for i in xrange(i, len(vmlinux)):
		if ord(vmlinux[i]):
			break
	offset = i-2

	do_token_index_table(kallsyms , offset, vmlinux)

def do_marker_table(kallsyms, offset, vmlinux):
	kallsyms['marker_table'] = offset
	print '[+] kallsyms_marker_table = ', hex(offset)

	offset += (((kallsyms['numsyms']-1)>>8)+1)*(kallsyms['arch']/8)
	offset = STRIPZERO(offset, vmlinux)

	do_token_table(kallsyms, offset, vmlinux)


def do_type_table(kallsyms, offset, vmlinux):
	flag = True
	for i in xrange(offset,offset+256*4,4):
		if INT(i, vmlinux) & ~0x20202020 != 0x54545454:
			flag = False
			break

	if flag:
		kallsyms['type_table'] = offset

		while INT(offset, vmlinux):
			offset += (kallsyms['arch']/8)
		offset = STRIPZERO(offset, vmlinux)
	else:
		kallsyms['type_table'] = 0

	print '[+] kallsyms_type_table = ', hex(kallsyms['type_table'])

	offset -= 4
	do_marker_table(kallsyms, offset, vmlinux)

def do_name_table(kallsyms, offset, vmlinux):
	kallsyms['name_table'] = offset
	print '[+] kallsyms_name_table = ', hex(offset)

	for i in xrange(kallsyms['numsyms']):
		length = ord(vmlinux[offset])
		offset += length+1
	while offset%4 != 0:
		offset += 1
	offset = STRIPZERO(offset, vmlinux)

	do_type_table(kallsyms, offset, vmlinux)

	# decompress name and type
	name_offset = 0
	for i in xrange(kallsyms['numsyms']):
		offset = kallsyms['name_table']+name_offset
		length = ord(vmlinux[offset])

		offset += 1
		name_offset += length+1

		name = ''
		while length:
			token_index_table_offset = ord(vmlinux[offset])
			xoffset = kallsyms['token_index_table']+token_index_table_offset*2
			token_table_offset = SHORT(xoffset, vmlinux)
			strptr = kallsyms['token_table']+token_table_offset

			while ord(vmlinux[strptr]):
				name += '%c' % ord(vmlinux[strptr])
				strptr += 1

			length -= 1
			offset += 1

		if kallsyms['type_table']:
			kallsyms['type'].append('X')
			kallsyms['name'].append(name)
		else:
			kallsyms['type'].append(name[0])
			kallsyms['name'].append(name[1:])

def do_guess_start_address(kallsyms, vmlinux):
	_startaddr_from_xstext = 0
	_startaddr_from_banner = 0
	_startaddr_from_processor = 0

	for i in xrange(kallsyms['numsyms']):
		if kallsyms['name'][i] in ['_text', 'stext', '_stext', '_sinittext', '__init_begin']:
			if hex(kallsyms['address'][i]):
				if _startaddr_from_xstext==0 or kallsyms['address'][i]<_startaddr_from_xstext:
					_startaddr_from_xstext = kallsyms['address'][i]

		elif kallsyms['name'][i] == 'linux_banner':
			linux_banner_addr = kallsyms['address'][i]
			linux_banner_fileoffset = vmlinux.find('Linux version ')
			if linux_banner_fileoffset:
				_startaddr_from_banner = linux_banner_addr - linux_banner_fileoffset

		elif kallsyms['name'][i] == '__lookup_processor_type_data':
			lookup_processor_addr = kallsyms['address'][i]

			step = kallsyms['arch'] / 8
			if kallsyms['arch'] == 32:
				addr_base = 0xC0008000
			else:
				addr_base = 0xffffffc000080000

			for i in xrange(0,0x100000,step):
				_startaddr_from_processor = addr_base + i
				fileoffset = lookup_processor_addr - _startaddr_from_processor
				if lookup_processor_addr == INT(fileoffset, vmlinux):
					break

			if _startaddr_from_processor == _startaddr_from_processor+0x100000:
				_startaddr_from_processor = 0

	if _startaddr_from_banner:
		kallsyms['_start'] = _startaddr_from_banner
	elif _startaddr_from_processor:
		kallsyms['_start'] = _startaddr_from_processor
	elif _startaddr_from_xstext:
		kallsyms['_start'] = _startaddr_from_xstext

	if kallsyms['arch']==64 and _startaddr_from_banner!=_startaddr_from_xstext:
		 kallsyms['_start'] = 0xffffffc000000000 + INT(8, vmlinux)


	kallsyms_guess_start_addresses = [hex(0xffffffc000000000 + INT(8, vmlinux)), hex(_startaddr_from_xstext), hex(_startaddr_from_banner), hex(_startaddr_from_processor)]

	if len(set(kallsyms_guess_start_addresses)) == 1:
		print '[+] kallsyms_guess_start_addresses = ', kallsyms_guess_start_addresses[0]
	else:
		print '[+] kallsyms_guess_start_addresses = ',  hex(0xffffffc000000000 + INT(8, vmlinux)) if kallsyms['arch']==64 else '', hex(_startaddr_from_xstext), hex(_startaddr_from_banner), hex(_startaddr_from_processor)

	return kallsyms['_start']

# XXX: is this looking for address table??
def do_address_table(kallsyms, offset, vmlinux):
	step = kallsyms['arch'] / 8
	if kallsyms['arch'] == 32:
		addr_base = 0xC0000000
	else:
		addr_base = 0xffffffc000000000

	kallsyms['address'] = []
	for i in xrange(offset, len(vmlinux), step):
		addr = INT(i, vmlinux)
		if addr < addr_base:
			return (i-offset)/step
		else:
			kallsyms['address'].append(addr)

	return 0

def do_kallsyms(kallsyms, vmlinux):
	step = kallsyms['arch'] / 8

	offset = 0
	vmlen  = len(vmlinux) # OK

	while offset+step < vmlen:
		num = do_address_table(kallsyms, offset, vmlinux) # XXX: working?
		if num > 40000:
			kallsyms['numsyms'] = num
			break
		else:
			offset += (num+1)*step

	if kallsyms['numsyms'] == 0:
		log(3, '[!]lookup_address_table error...')
		return

	kallsyms['address_table'] = offset
	print '[+] kallsyms_address_table = ', hex(offset)

	offset += kallsyms['numsyms']*step
	offset = STRIPZERO(offset, vmlinux, step)
	num = INT(offset, vmlinux)
	offset += step

	print '[+] kallsyms_num = ', kallsyms['numsyms'], num
	if abs(num-kallsyms['numsyms']) > 128:
			kallsyms['numsyms'] = 0
			print '  [!]not equal, maybe error...'
			return

	if num > kallsyms['numsyms']:
		for i in xrange(kallsyms['numsyms'],num):
			kallsyms['address'].insert(0,0)
		kallsyms['numsyms'] = num

	offset = STRIPZERO(offset, vmlinux)
	do_name_table(kallsyms, offset, vmlinux)
	do_guess_start_address(kallsyms, vmlinux)
	return

def do_get_arch(kallsyms, bv):
	def fuzzy_arm64(bv):
		step = 8
		offset = 0
		vmlen  = len(bv) - len(bv)%8
		addr_base = 0xffffffc000000000
		while offset+step < vmlen:
		  for i in xrange(offset, vmlen, step):
				if INT64(i, bv) < addr_base:
					addrnum = (i-offset)/step
					if addrnum > 10000:
						return True
					else:
						offset = i+step
		return False

	# only mode we will support
	if re.search('ARMd', bv[:0x200]):
		kallsyms['arch'] = 64

	'''

	elif fuzzy_arm64(bv):
		kallsyms['arch'] = 64

	else:
		kallsyms['arch'] = 32
	'''
	return False # this is messy, but can integrate into binaryninja

	print '[+] kallsyms_arch = ', kallsyms['arch']

#/////////////


def print_kallsyms(kallsyms, vmlinux):
	buf = '\n'.join( '%x %c %s'%(kallsyms['address'][i],kallsyms['type'][i],kallsyms['name'][i]) for i in xrange(kallsyms['numsyms']) )
	open('kallsyms','w').write(buf)

#////////////////////////////////////////////////////////////////////////////////////////////

def accept_file(li, n):
	"""
	Check if the file is of supported format

	@param li: a file-like object which can be used to access the input data
	@param n : format number. The function will be called with incrementing
			   number until it returns zero
	@return: 0 - no more supported formats
			 string "name" - format name to display in the chooser dialog
			 dictionary { 'format': "name", 'options': integer }
			   options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
			   to indicate preferred format
	"""

	# we support only one format per file
	if n > 0:
		return 0

	# magic = li.read(8)
	# if magic != 'ANDROID!':
	#	 return 0

	return "Android OS Kernel(ARM)"

def load_file(li, neflags, format):
	"""
	Load the file into database

	@param li: a file-like object which can be used to access the input data
	@param neflags: options selected by the user, see loader.hpp
	@return: 0-failure, 1-ok
	"""

	li.seek(0)
	vmlinux = li.read(li.size())

	do_get_arch(kallsyms, vmlinux)
	do_kallsyms(kallsyms, vmlinux)
	# print_kallsyms(kallsyms, vmlinux)

	if kallsyms['numsyms'] == 0:
		print '[!]get kallsyms error...'
		return 0

	print '[+] kallsyms_start_address = ', hex(kallsyms['_start'])

	idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
	li.file2base(0, kallsyms['_start'], kallsyms['_start']+li.size(), True)

	s = idaapi.segment_t()
	s.bitness = kallsyms['arch'] / 32
	s.startEA = kallsyms['_start']
	s.endEA = kallsyms['_start']+li.size()
	idaapi.add_segm_ex(s,".text","CODE",ADDSEG_OR_DIE)

	for i in xrange(kallsyms['numsyms']):
		if kallsyms['type'][i] in ['t','T']:
			idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 1)
		else:
			idaapi.add_entry(kallsyms['address'][i], kallsyms['address'][i], kallsyms['name'][i], 0)

	print "Android vmlinux loaded..."
	return 1

#////////////////////////////////////////////////////////////////////////////////////////////

def help():
	print 'Usage:  droidimg.py [vmlinux FILE]\n'
	exit()

def droidimg(bv, offset):
	vmlinux = bv.file.raw.read(0, len(bv))

	do_get_arch(kallsyms, bv) # TODO: port to "bv" for the sake of "is_valid_for_data"
	# do_kallsyms(kallsyms, vmlinux) # vmlinux => bv # TODO: work on this..

	# TODO: reenable this...
	'''
	if kallsyms['numsyms'] > 0:
		print_kallsyms(kallsyms, bv) # vmlinux => bv

	else:
		print '[!]get kallsyms error...'
	'''

	# if it fails i'ts not a valid vmlinux...
