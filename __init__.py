# -*- coding: utf-8 -*-
# original author: nforest@k33nteam.org

import os
import re
import sys
import time
import struct

from binaryninja import *

rebase = False

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

class kallsyms_handler(BackgroundTaskThread):
	def __init__(self, kallsyms, bv):
		BackgroundTaskThread.__init__(self, "kallsyms_handler initiated", True)
		self.kallsyms = kallsyms
		self.bv = bv

	def run(self):
		kallsyms = self.kallsyms
		bv = self.bv

		# FIXME: split it up...
		#for idx in xrange(kallsyms['numsyms']):
		for idx in xrange(50): # FIXME: this is not working...
			# keep this
			if kallsyms['type'][idx] not in ["T", "t"]:
				continue

			# NOTE: the logging IS working
			#reference = "%x %c %s" % (kallsyms['address'][idx], kallsyms['type'][idx], kallsyms['name'][idx])
			#log(2, reference) # working...
			#log(2, rebase) # working...

			function_address = kallsyms['address'][idx] - 0xffffffc000080000

			# rebase is correct value during testing...
			if rebase:
				function_address = kallsyms['address'][idx]

			# XXX: why isn't this working...
			bv.define_auto_symbol(Symbol(FunctionSymbol, function_address, kallsyms['name'][idx]))
			bv.add_function(Architecture['aarch64'].standalone_platform, function_address)

class AndroidKernelView(BinaryView):
	name = "Android Kernel"
	long_name = "Android Kernel"

	def __init__(self, bv):
		BinaryView.__init__(self, parent_view = bv, file_metadata = bv.file)
		self.raw = bv

		# vmlinux is the right size...
		vmlinux = bv.read(0, len(bv)) # FIXME super inefficient FIXME
		do_kallsyms(kallsyms, vmlinux) # TODO: work on this..

		# kallsyms_handler doesn't work....
		#s = kallsyms_handler(kallsyms, bv) # FIXME: doesn't seem to be working...
		#s.start()

		#'''
		#for idx in xrange(kallsyms['numsyms']): # FIXME: need to do this, but it will FREEZE the program
		for idx in xrange(50): # FIXME: this is bad...
			# keep this
			if kallsyms['type'][idx] not in ["T", "t"]:
				continue

			function_address = kallsyms['address'][idx] - 0xffffffc000080000

			if rebase:
				function_address = kallsyms['address'][idx]

			#reference = "0x%x %c %s" % (function_address, kallsyms['type'][idx], kallsyms['name'][idx])
			#log(2, reference)

			self.define_auto_symbol(Symbol(FunctionSymbol, function_address, kallsyms['name'][idx]))
			self.add_function(Architecture['aarch64'].standalone_platform, function_address)
		#'''

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

		# rebase?? is this right??
		entry_point = 0
		if rebase:
			entry_point = 0xffffffc000080000

		self.add_entry_point(Architecture['aarch64'].standalone_platform, entry_point)

		return True

	#def perform_is_valid_offset(self, addr):
	#	if (addr >= 0x8000) and (addr < 0x10000):
	#		return True
	#	return False

	# very important
	def perform_read(self, addr, length):

		# XXX: does rebase effect this??
		if rebase:
			# rebase - is this right??
			addr -= 0xffffffc000080000

		if addr < 0:
			return False

		return self.raw.read(addr, length)

	def perform_is_executable(self):
		return True

class AndroidKernelViewBank(AndroidKernelView):
	name = "Android kernel"
	long_name = "Android kernel"

	def __init__(self, data):
		AndroidKernelView.__init__(self, data)

AndroidKernelViewBank.register()

def INT(offset, vmlinux):
	size = kallsyms['arch'] / 8
	s = vmlinux[offset:offset+size]
	f = 'I' if bytes==4 else 'Q'
	(num,) = struct.unpack(f, s)
	return num

def INT32(offset, vmlinux):
	s = vmlinux[offset:offset+4]
	(num,) = struct.unpack('I', s)
	return num

def INT64(offset, vmlinux):
	s = vmlinux[offset:offset+8]
	(num,) = struct.unpack('Q', s)
	return num

def SHORT(offset, vmlinux):
	s = vmlinux[offset:offset+2]
	(num,) = struct.unpack('H', s)
	return num

def STRIPZERO(offset, vmlinux, step=4):
	NOTZERO = INT32 if step==4 else INT
	for i in xrange(offset,len(vmlinux),step):
		if NOTZERO(i, vmlinux):
			return i

#//////////////////////
def do_token_index_table(kallsyms, offset, vmlinux):
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
	"""
	vmlinux is self.raw

	returns number of symbols, but if it's less than 40k we don't care so lets return False instead

	"""

	step = kallsyms['arch'] / 8

	addr_base = 0xffffffc000000000

	# currently only suport aarch64
	#if kallsyms['arch'] == 32:
	#	addr_base = 0xC0000000

	kallsyms['address'] = []
	for i in xrange(offset, len(vmlinux), step):
		addr = INT(i, vmlinux) # FIXME: failed here
		if addr < addr_base:
			return (i-offset)/step
		else:
			kallsyms['address'].append(addr)

	return 0

# TAKES ~3 seconds to run entire program via cmdline
def do_kallsyms(kallsyms, vmlinux):
	"""
		first function executed

		[address_table][??]

		vmlinux is self.raw....

	"""
	kallsyms['arch'] = 64 # assert(kallsyms['arch'] == 64)

	step = kallsyms['arch'] / 8

	offset = 0
	vmlen = len(vmlinux)
	while offset+step < vmlen:
		num = do_address_table(kallsyms, offset, vmlinux)
		if num > 40000:
			kallsyms['numsyms'] = num
			break
		else:
			offset += (num+1)*step

	if kallsyms['numsyms'] == 0:
		print '[!]lookup_address_table error...'
		return

	kallsyms['address_table'] = offset
	print '[+]kallsyms_address_table = ', hex(offset)

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
	return False #  messy, but for binaryninja integration

	print '[+] kallsyms_arch = ', kallsyms['arch']
