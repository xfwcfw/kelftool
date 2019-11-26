/*
 * Copyright (c) 2019 xfwcfw
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __KELF_H__
#define __KELF_H__

#include "keystore.h"

#define KELF_ERROR_INVALID_DES_KEY_COUNT -1
#define KELF_ERROR_INVALID_HEADER_SIGNATURE -2
#define KELF_ERROR_INVALID_BIT_TABLE_SIZE -3
#define KELF_ERROR_INVALID_BIT_TABLE_SIGNATURE -4
#define KELF_ERROR_INVALID_ROOT_SIGNATURE -5
#define KELF_ERROR_INVALID_CONTENT_SIGNATURE -6
#define KELF_ERROR_UNSUPPORTED_FILE -6

#define SYSTEM_TYPE_PS2 0 // same for COH (arcade)
#define SYSTEM_TYPE_PSX 1

#pragma pack(push, 1)
struct KELFHeader
{
	uint8_t UserDefined[16];
	uint32_t ContentSize; // Sometimes not...
	uint16_t HeaderSize;
	uint8_t SystemType;
	uint8_t ApplicationType;
	uint16_t Flags;
	uint16_t BitCount;
	uint32_t MGZones;
};

#define BIT_BLOCK_ENCRYPTED 1
#define BIT_BLOCK_SIGNED 2

struct BitTable
{
	uint32_t HeaderSize;
	uint8_t BlockCount;
	uint8_t gap[3];

	struct BitBlock
	{
		uint32_t Size;
		uint32_t Flags;
		uint8_t Signature[8];
	} Blocks[256];
};

#pragma pack(pop)

class Kelf
{
	KeyStore ks;
	std::string Kbit;
	std::string Kc;
	BitTable bitTable;
	std::string Content;
public:
	Kelf(KeyStore& _ks) : ks(_ks) { }

	int LoadKelf(std::string filename);
	int SaveKelf(std::string filename);
	int LoadContent(std::string filename);
	int SaveContent(std::string filename);

	std::string GetHeaderSignature(KELFHeader& header);
	std::string DeriveKeyEncryptionKey(KELFHeader& header);
	void DecryptKeys(std::string KEK);
	void EncryptKeys(std::string KEK);
	std::string GetBitTableSignature();
	std::string GetRootSignature(std::string HeaderSignature, std::string BitTableSignature);
	void DecryptContent(int keycount);
	int VerifyContentSignature();
};

#endif