# -*- coding: utf-8 -*-
# ported code from https://github.com/nforest/droidimg

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

class AndroidKernelView(BinaryView):
	name = "Android Kernel"
	long_name = "Android Kernel"

	def __init__(self, bv):
		BinaryView.__init__(self, parent_view = bv, file_metadata = bv.file)
		self.raw = bv
		self.kallsyms = kallsyms

		# TODO: maybe move kallsyms_handler out of AndroidKernelView
		s = kallsyms_handler(self, kallsyms)
		s.start()

	def do_kallsyms(self):
		"""
			first function executed

		"""

		self.kallsyms['arch'] = 64
		step = self.kallsyms['arch'] / 8

		offset = 0
		vmlen = len(self.vmlinux)
		while offset+step < vmlen:
			num = self.do_address_table(offset)
			if num > 40000:
				self.kallsyms['numsyms'] = num
				break
			else:
				offset += (num+1)*step

		if self.kallsyms['numsyms'] == 0:
			print '[!] lookup_address_table error...'
			return

		self.kallsyms['address_table'] = offset
		#print '[+] kallsyms_address_table = ', hex(offset) # TODO: use this

		offset += self.kallsyms['numsyms']*step
		offset = STRIPZERO(self.vmlinux, offset, step)
		num = INT(offset, self.vmlinux)
		offset += step

		#print '[+] kallsyms_num = ', self.kallsyms['numsyms'], num # TODO: use this
		if abs(num-self.kallsyms['numsyms']) > 128:
				self.kallsyms['numsyms'] = 0
				print '  [!] not equal, maybe error...'
				return

		if num > self.kallsyms['numsyms']:
			for i in xrange(self.kallsyms['numsyms'],num):
				self.kallsyms['address'].insert(0,0)
			self.kallsyms['numsyms'] = num

		offset = STRIPZERO(self.vmlinux, offset)
		self.do_name_table(offset)
		self.do_guess_start_address()

	# vmlinux is MUCH faster than using bv..
	def do_address_table(self, offset):
		"""
		vmlinux is self.raw

		returns number of symbols, but if it's less than 40k we don't care so lets return False instead

		"""

		step = self.kallsyms['arch'] / 8

		addr_base = 0xffffffc000000000

		# currently only suport aarch64
		#if kallsyms['arch'] == 32:
		#	addr_base = 0xC0000000

		self.kallsyms['address'] = []
		for i in xrange(offset, len(self.vmlinux), step):
			addr = INT(i, self.vmlinux)
			if addr < addr_base:
				return (i-offset)/step
			else:
				self.kallsyms['address'].append(addr)

		return 0

	def do_name_table(self, offset):
		self.kallsyms['name_table'] = offset
		#print '[+] kallsyms_name_table = ', hex(offset) # TODO: use this

		for i in xrange(self.kallsyms['numsyms']):
			length = ord(self.vmlinux[offset])
			offset += length + 1
		while offset%4 != 0:
			offset += 1
		offset = STRIPZERO(self.vmlinux, offset)

		self.do_type_table(offset)

		# decompress name and type
		name_offset = 0
		for i in xrange(self.kallsyms['numsyms']):
			offset = self.kallsyms['name_table'] + name_offset
			length = ord(self.vmlinux[offset])

			offset += 1
			name_offset += length+1

			name = ''
			while length:
				token_index_table_offset = ord(self.vmlinux[offset])
				xoffset = self.kallsyms['token_index_table'] + token_index_table_offset*2
				token_table_offset = SHORT(xoffset, self.vmlinux)
				strptr = self.kallsyms['token_table'] + token_table_offset

				while ord(self.vmlinux[strptr]):
					name += '%c' % ord(self.vmlinux[strptr])
					strptr += 1

				length -= 1
				offset += 1

			if self.kallsyms['type_table']:
				self.kallsyms['type'].append('X')
				self.kallsyms['name'].append(name)
			else:
				self.kallsyms['type'].append(name[0])
				self.kallsyms['name'].append(name[1:])

	def do_guess_start_address(self):
		_startaddr_from_xstext = 0
		_startaddr_from_banner = 0
		_startaddr_from_processor = 0

		for i in xrange(self.kallsyms['numsyms']):
			if self.kallsyms['name'][i] in ['_text', 'stext', '_stext', '_sinittext', '__init_begin']:
				if hex(self.kallsyms['address'][i]):
					if _startaddr_from_xstext==0 or self.kallsyms['address'][i]<_startaddr_from_xstext:
						_startaddr_from_xstext = self.kallsyms['address'][i]

			# commenting this out because "find" may be annoying to implement for now...
			#elif kallsyms['name'][i] == 'linux_banner':
			#	linux_banner_addr = kallsyms['address'][i]
			#	linux_banner_fileoffset = self.vmlinux.find('Linux version ') # FIXME: use "bv" instead. TODO: bv needs "find"

				#
				# https://github.com/Vector35/binaryninja-api/blob/dev/python/__init__.py
				# "class BinaryView" needs "find"
				# if I use "get_string", it will be effected by rebasing..

			#	if linux_banner_fileoffset:
			#		_startaddr_from_banner = linux_banner_addr - linux_banner_fileoffset

			elif self.kallsyms['name'][i] == '__lookup_processor_type_data':
				lookup_processor_addr = self.kallsyms['address'][i]

				step = self.kallsyms['arch'] / 8
				if self.kallsyms['arch'] == 32:
					addr_base = 0xC0008000
				else:
					addr_base = 0xffffffc000080000

				for i in xrange(0,0x100000,step):
					_startaddr_from_processor = addr_base + i
					fileoffset = lookup_processor_addr - _startaddr_from_processor
					if lookup_processor_addr == INT(fileoffset, self.vmlinux):
						break

				if _startaddr_from_processor == _startaddr_from_processor+0x100000:
					_startaddr_from_processor = 0

		#if _startaddr_from_banner:
		#	self.kallsyms['_start'] = _startaddr_from_banner
		if _startaddr_from_processor: # was an "elif" statement
			self.kallsyms['_start'] = _startaddr_from_processor
		elif _startaddr_from_xstext:
			self.kallsyms['_start'] = _startaddr_from_xstext

		if self.kallsyms['arch']==64 and _startaddr_from_banner!=_startaddr_from_xstext:
			 self.kallsyms['_start'] = 0xffffffc000000000 + INT(8, self.vmlinux)

		#kallsyms_guess_start_addresses = [hex(0xffffffc000000000 + INT(8, self.vmlinux)), hex(_startaddr_from_xstext), hex(_startaddr_from_banner), hex(_startaddr_from_processor)]
		kallsyms_guess_start_addresses = [hex(0xffffffc000000000 + INT(8, self.vmlinux)), hex(_startaddr_from_xstext), hex(_startaddr_from_processor)]

		# TODO: use this
		'''
		if len(set(kallsyms_guess_start_addresses)) == 1:
			print '[+] kallsyms_guess_start_addresses = ', kallsyms_guess_start_addresses[0]
		else:
			# print '[+] kallsyms_guess_start_addresses = ',  hex(0xffffffc000000000 + INT(8, self.vmlinux)) if kallsyms['arch']==64 else '', hex(_startaddr_from_xstext), hex(_startaddr_from_banner), hex(_startaddr_from_processor)
			print '[+] kallsyms_guess_start_addresses = ',  hex(0xffffffc000000000 + INT(8, self.vmlinux)) if self.kallsyms['arch']==64 else '', hex(_startaddr_from_xstext), hex(_startaddr_from_processor)
		'''

		#
		# TODO: kallsyms_guess_start_addresses will be used for rebase
		#

		return kallsyms['_start']

	def do_token_index_table(self, offset):
		self.kallsyms['token_index_table'] = offset
		# print '[+] kallsyms_token_index_table = ', hex(offset) # TODO: use this

	def do_token_table(self, offset):
		self.kallsyms['token_table'] = offset
		# print '[+] kallsyms_token_table = ', hex(offset) # TODO: use this

		for i in xrange(offset, len(self.vmlinux)):
			if SHORT(i, self.vmlinux) == 0:
				break
		for i in xrange(i, len(self.vmlinux)):
			if ord(self.vmlinux[i]):
				break
		offset = i-2

		self.do_token_index_table(offset)

	def do_marker_table(self, offset):
		self.kallsyms['marker_table'] = offset
		# print '[+] kallsyms_marker_table = ', hex(offset) # TODO: use this

		offset += (((self.kallsyms['numsyms']-1)>>8)+1) * (self.kallsyms['arch']/8)
		offset = STRIPZERO(self.vmlinux, offset)

		self.do_token_table(offset)

	def do_type_table(self, offset):
		flag = True
		for i in xrange(offset, offset+256*4, 4):
			if INT(i, self.vmlinux) & ~0x20202020 != 0x54545454:
				flag = False
				break

		if flag:
			self.kallsyms['type_table'] = offset

			while INT(offset, self.vmlinux):
				offset += (self.kallsyms['arch']/8)
			offset = STRIPZERO(self.vmlinux, offset)
		else:
			self.kallsyms['type_table'] = 0

		# print '[+] kallsyms_type_table = ', hex(self.kallsyms['type_table']) # TODO: use this

		offset -= 4
		self.do_marker_table(offset)

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


class kallsyms_handler(BackgroundTaskThread, AndroidKernelView):
	# __init__ isn't threaded AFAIK, so keep heavy lifting out if it.
	def __init__(self, bv, kallsyms):
		BackgroundTaskThread.__init__(self, "kallsyms_handler initiated", True)
		self.kallsyms = kallsyms
		self.bv = bv

	def run(self):
		# using vmlinux instead of bv is actually MUCH FASTER
		self.vmlinux = self.bv.read(0, len(self.bv.file.raw))

		# TODO: thread do_kallsyms better
		self.do_kallsyms() # TODO: work on this..

		for idx in xrange(kallsyms['numsyms']):
			# keep this
			if self.kallsyms['type'][idx] not in ["T", "t"]:
				continue

			#reference = "%x %c %s" % (self.kallsyms['address'][idx], self.kallsyms['type'][idx], self.kallsyms['name'][idx])
			#log(2, reference) # working...
			#log(2, rebase) # working...

			function_address = self.kallsyms['address'][idx] - 0xffffffc000080000

			# rebase is correct value during testing...
			if rebase:
				function_address = self.kallsyms['address'][idx]

			self.bv.define_auto_symbol(Symbol(FunctionSymbol, function_address, self.kallsyms['name'][idx]))
			self.bv.add_function(Architecture['aarch64'].standalone_platform, function_address)

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

def STRIPZERO(vmlinux, offset, step=4):
	NOTZERO = INT32 if step==4 else INT
	for i in xrange(offset,len(vmlinux),step):
		if NOTZERO(i, vmlinux):
			return i
