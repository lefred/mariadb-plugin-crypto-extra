# Copyright (c) 2019, MariaDB corporation. All rights reserved.
# Copyright (c) 2026, lefred (Frédéric Descamps). All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1335  USA

INCLUDE(CheckIncludeFiles)
INCLUDE(CheckLibraryExists)

CHECK_INCLUDE_FILES(argon2.h HAVE_ARGON2_H)
CHECK_LIBRARY_EXISTS(argon2 argon2id_hash_encoded "" HAVE_LIBARGON2)

IF(NOT WITH_SSL STREQUAL "no" AND HAVE_ARGON2_H AND HAVE_LIBARGON2)
  ADD_DEFINITIONS(${SSL_DEFINES})
  IF(WITH_SSL STREQUAL "bundled")
    MYSQL_ADD_PLUGIN(crypto_extra crypto_extra.cc STATIC_ONLY
                     LINK_LIBRARIES argon2)
  ELSE()
    MYSQL_ADD_PLUGIN(crypto_extra crypto_extra.cc MODULE_ONLY
                     RECOMPILE_FOR_EMBEDDED
                     LINK_LIBRARIES ${SSL_LIBRARIES} argon2)
  ENDIF()
ELSE()
  MESSAGE(STATUS
          "crypto_extra disabled: OpenSSL and libargon2 development files are required")
ENDIF()
