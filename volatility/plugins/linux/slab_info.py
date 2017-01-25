# Volatility
#
#print (slab.s_mem.v() + i * cache.buffer_size)
#print (slab.s_mem.v() + i * cache.buffer_size)
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Joe Sylve
@license:      GNU General Public License 2.0
@contact:      joe.sylve@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import os
import volatility.debug as debug
import volatility.plugins.linux.common as linux_common

DEBUG_SLAB = 'sock_inode_cache'
DEBUG_LOC = 3982780416
DEBUG_LOCS = [3880307712, 3880300544, 3880301568, 3880302592, 3880303616, 3880292352, 3880293376, 3880294400, 3880295424, 3880288256, 3880289280, 3880290304, 3880291328, 3880284160, 3880285184, 3880286208, 3880287232, 3880280064, 3880281088, 3880282112, 3880283136, 3880271872, 3880272896, 3880273920, 3880274944, 3880263680, 3880264704, 3880265728, 3880266752, 3880259584, 3880260608, 3880261632, 3880262656, 3880255488, 3880256512, 3880257536, 3880258560, 3880382464, 3880383488, 3880384512, 3880385536, 3880378368, 3880379392, 3880380416, 3880381440, 3880374272, 3880375296, 3880376320, 3880377344, 3880370176, 3880371200, 3880372224, 3880373248, 3880333312, 3880334336, 3880335360, 3880336384, 3880325120, 3880326144, 3880327168, 3880328192, 3880321024, 3880322048, 3880323072, 3880324096, 3880038400, 3880039424, 3880040448, 3880041472, 3880034304, 3880035328, 3880036352, 3880037376, 3912355840, 3912356864, 3912357888, 3912358912, 3912351744, 3912352768, 3912353792, 3912354816, 3909677056, 3909678080, 3909679104, 3909680128, 3909672960, 3909673984, 3909675008, 3909676032, 3911725056, 3911726080, 3911727104, 3911728128, 3911720960, 3911721984, 3911723008, 3911724032, 3880252416, 3880253440, 3880254464, 3974692864, 3974693888, 3974694912, 3974695936, 3879940096, 3879941120, 3879942144, 3879943168, 3982778368, 3982779392, 3982780416, 3982781440, 3986116608, 3986117632, 3986118656, 3986119680, 3978129408, 3978130432, 3978131456, 3978132480, 3911503872, 3911504896, 3986148352, 3986147328, 3986146304, 3986145280, 3880304640, 3880305664, 3880306688]

class kmem_cache(obj.CType):
    def get_type(self):
        raise NotImplementedError

    def get_name(self):
        return str(self.name.dereference_as("String", length = 255))

class kmem_cache_slab(kmem_cache):
    def get_type(self):
        return "slab"

    # volatility does not support indexing pointers
    # and the definition of nodelists changes from array to pointer
    def _get_nodelist(self):
        ent = self.nodelists

        if type(ent) == obj.Pointer:
            ret = obj.Object("kmem_list3", offset = ent.dereference(), vm = self.obj_vm)

        elif type(ent) == obj.Array:
            ret = ent[0]
        else:
            debug.error("Unknown nodelists types. %s" % type(ent))

        return ret

    def _get_free_list(self):

        slablist = self._get_nodelist().slabs_free

        for slab in slablist.list_of_type("slab", "list"):
            yield slab

    def _get_partial_list(self):
        slablist = self._get_nodelist().slabs_partial

        for slab in slablist.list_of_type("slab", "list"):
            yield slab

    def _get_full_list(self):
        slablist = self._get_nodelist().slabs_full

        for slab in slablist.list_of_type("slab", "list"):
            yield slab

    def _get_object(self, offset):
        return obj.Object(self.struct_type,
                            offset = offset,
                            vm = self.obj_vm,
                            parent = self.obj_parent,
                            name = self.struct_type)
    def __repr__(self):
        objs = []
        for slab in self._get_full_list():
            for i in range(self.num):
                objs += ['0x'+'%02x'%(slab.s_mem.v() + i * self.buffer_size)]
                t = slab.s_mem.v() + i * self.buffer_size
                for d in range(len(DEBUG_LOCS)):
                    if (DEBUG_LOCS[d] >= t and DEBUG_LOCS[d] < t+self.buffer_size):
                        print "outp:Found the sk/packet_sock:",DEBUG_LOCS[d],"alloced"
                        DEBUG_LOCS.pop(d)
                        break


        for slab in self._get_partial_list():
            if not self.num or self.num == 0:
                return                

            bufctl = obj.Object("Array",
                        offset = slab.v() + slab.size(),
                        vm = self.obj_vm,
                        parent = self.obj_parent,
                        targetType = "unsigned int",
                        count = self.num)

            unallocated = [0] * self.num

            i = slab.free
            while i != 0xFFFFFFFF:
                if i >= self.num:
                    break
                unallocated[i] = 1
                i = bufctl[i]

            for i in range(bufctl.count):
                alloc = (unallocated[i] == 0)
                allocinfo = "unalloc"
                if alloc:
                    allocinfo = "alloced"
                    
                t = slab.s_mem.v() + i * self.buffer_size
                for d in range(len(DEBUG_LOCS)):
                    if (DEBUG_LOCS[d] >= t and DEBUG_LOCS[d] < t+self.buffer_size):
                        objs += ['0x'+'%02x'%(t)]
                        print "outp:Found the sk/packet_sock:",DEBUG_LOCS[d],allocinfo
                        DEBUG_LOCS.pop(d)
                        break
            
        return repr(objs)

    def __iter__(self):

        if not self.unalloc:
            for slab in self._get_full_list():
                for i in range(self.num):
                    yield self._get_object(slab.s_mem.v() + i * self.buffer_size)

        for slab in self._get_partial_list():
            if not self.num or self.num == 0:
                return                

            bufctl = obj.Object("Array",
                        offset = slab.v() + slab.size(),
                        vm = self.obj_vm,
                        parent = self.obj_parent,
                        targetType = "unsigned int",
                        count = self.num)

            unallocated = [0] * self.num

            i = slab.free
            while i != 0xFFFFFFFF:
                if i >= self.num:
                    break
                unallocated[i] = 1
                i = bufctl[i]

            for i in range(0, self.num):
                if unallocated[i] == self.unalloc:
                    yield self._get_object(slab.s_mem.v() + i * self.buffer_size)

        if self.unalloc:
            for slab in self._get_free_list():
                for i in range(self.num):
                    yield self._get_object(slab.s_mem.v() + i * self.buffer_size)

class LinuxKmemCacheOverlay(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'linux'}
    before = ['BasicObjectClasses'] # , 'LinuxVTypes']

    def modification(self, profile):

        if profile.get_symbol("cache_chain"):
            profile.object_classes.update({'kmem_cache': kmem_cache_slab})

class linux_slabinfo(linux_common.AbstractLinuxCommand):
    """Mimics /proc/slabinfo on a running machine"""

    def get_all_kmem_caches(self):
        linux_common.set_plugin_members(self)
        cache_chain = self.addr_space.profile.get_symbol("cache_chain")
        slab_caches = self.addr_space.profile.get_symbol("slab_caches")

        if cache_chain: #slab
            caches = obj.Object("list_head", offset = cache_chain, vm = self.addr_space)
            listm = "next"
            ret = [cache for cache in caches.list_of_type("kmem_cache", listm)]
        elif slab_caches: #slub
            debug.info("SLUB is currently unsupported.")
            ret = []
        else:
            debug.error("Unknown or unimplemented slab type.")

        return ret

    def get_kmem_cache(self, cache_name, unalloc, struct_name = ""):

        if struct_name == "":
            struct_name = cache_name

        for cache in self.get_all_kmem_caches():
            if cache.get_name() == cache_name:
                cache.newattr("unalloc", unalloc)
                cache.newattr("struct_type", struct_name)
                return cache

        debug.debug("Invalid kmem_cache: {0}".format(cache_name))
        return []

    def calculate(self):
        global DEBUG_LOCS
        linux_common.set_plugin_members(self)

        for cache in self.get_all_kmem_caches():
            if cache.get_type() == "slab":
                if os.path.isfile("/home/marto/getnode") and "size" in cache.get_name():
                    DEBUG_LOCS=[int(open("/home/marto/getnode").read().rstrip())]
                    repr(cache)

                if os.path.isfile("/home/marto/dosearch") and "size-1024" in cache.get_name():
                    print repr(cache)

                if os.path.isfile("/home/marto/sockloc") and cache.get_name() == DEBUG_SLAB:
                    print cache.get_name()
                    print cache.buffer_size
                    print len(eval(repr(cache)))

                if os.path.isfile("/home/marto/addr1024") and "size-1024" in cache.get_name():
                    print "!!!"
                    print repr(cache)
                    print "!!!"

                active_objs = 0
                active_slabs = 0
                num_slabs = 0
                # shared_avail = 0


                cnt = 0;
                for slab in cache._get_full_list():
                    if os.path.isfile("/home/marto/sockloc") and cache.get_name() == DEBUG_SLAB:
                        for i in range(cache.num):
                            print "outp:"+str(slab.s_mem.v() + i*cache.buffer_size)

                    active_objs += cache.num
                    active_slabs += 1

                for slab in cache._get_partial_list():
                    if os.path.isfile("/home/marto/sockloc") and cache.get_name() == DEBUG_SLAB:
                        for i in range(cache.num):
                            print "outp:"+str(slab.s_mem.v() + i*cache.buffer_size)

                    active_objs += slab.inuse
                    active_slabs += 1

                for slab in cache._get_free_list():
                    num_slabs += 1

                num_slabs += active_slabs
                num_objs = num_slabs * cache.num

                yield [cache.get_name(),
                        active_objs,
                        num_objs,
                        cache.buffer_size,
                        cache.num,
                        1 << cache.gfporder,
                        active_slabs,
                        num_slabs]

                #print "Remaining alloc locs?", len(DEBUG_LOCS)

    def render_text(self, outfd, data):
        self.table_header(outfd, [("<name>", "<30"),
                                  ("<active_objs>", "<13"),
                                  ("<num_objs>", "<10"),
                                  ("<objsize>", "<10"),
                                  ("<objperslab>", "<12"),
                                  ("<pagesperslab>", "<15"),
                                  ("<active_slabs>", "<14"),
                                  ("<num_slabs>", "<7"),
                                  ])

        for info in data:
            self.table_row(outfd, info[0], info[1], info[2], info[3], info[4], info[5], info[6], info[7])
