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
#include <openssl/des.h>
#include <string.h>

#include "kelf.h"

uint8_t MG_IV_NULL[8] = { 0 };

int TdesCbcCfb64Encrypt(void* Result, const void* Data, size_t Length, const void* Keys, int KeyCount, const void *IV)
{
	DES_key_schedule sc1;
	DES_key_schedule sc2;
	DES_key_schedule sc3;

	DES_set_key((const_DES_cblock*)Keys, &sc1);
	if (KeyCount >= 2)
		DES_set_key((const_DES_cblock*)((uint8_t*)Keys + 8), &sc2);
	if (KeyCount >= 3)
		DES_set_key((const_DES_cblock*)((uint8_t*)Keys + 16), &sc3);

	DES_cblock iv;
	memcpy(&iv, IV, 8);

	if (KeyCount == 1)
		DES_cbc_encrypt((uint8_t*)Data, (uint8_t*)Result, Length, &sc1, &iv, DES_ENCRYPT);
	if (KeyCount == 2)
		DES_ede2_cbc_encrypt((uint8_t*)Data, (uint8_t*)Result, Length, &sc1, &sc2, &iv, DES_ENCRYPT);
	if (KeyCount == 3)
		DES_ede3_cbc_encrypt((uint8_t*)Data, (uint8_t*)Result, Length, &sc1, &sc2, &sc3, &iv, DES_ENCRYPT);
	else
		return KELF_ERROR_INVALID_DES_KEY_COUNT;

	return 0;
}

int TdesCbcCfb64Decrypt(void* Result, const void* Data, size_t Length, const void* Keys, int KeyCount, const void* IV)
{
	DES_key_schedule sc1;
	DES_key_schedule sc2;
	DES_key_schedule sc3;

	DES_set_key((const_DES_cblock*)Keys, &sc1);
	if (KeyCount >= 2)
		DES_set_key((const_DES_cblock*)((uint8_t*)Keys + 8), &sc2);
	if (KeyCount >= 3)
		DES_set_key((const_DES_cblock*)((uint8_t*)Keys + 16), &sc3);

	DES_cblock iv;
	memcpy(&iv, IV, 8);

	if (KeyCount == 1)
		DES_cbc_encrypt((uint8_t*)Data, (uint8_t*)Result, Length, &sc1, &iv, DES_DECRYPT);
	if (KeyCount == 2)
		DES_ede2_cbc_encrypt((uint8_t*)Data, (uint8_t*)Result, Length, &sc1, &sc2, &iv, DES_DECRYPT);
	if (KeyCount == 3)
		DES_ede3_cbc_encrypt((uint8_t*)Data, (uint8_t*)Result, Length, &sc1, &sc2, &sc3, &iv, DES_DECRYPT);
	else
		return KELF_ERROR_INVALID_DES_KEY_COUNT;

	return 0;
}

void xor_bit(const void* a, const void* b, void* Result, size_t Length)
{
	size_t i;
	for (i = 0; i < Length; i++) {
		((uint8_t*)Result)[i] = ((uint8_t*)a)[i] ^ ((uint8_t*)b)[i];
	}
}

int Kelf::LoadKelf(std::string filename)
{
	FILE* f = fopen(filename.c_str(), "rb");

	KELFHeader header;
	fread(&header, sizeof(header), 1, f);

	if (header.Flags & 1 || header.Flags & 0xf0000 || header.BitCount != 0)
	{
		printf("This file is not supported yet and looked after.");
		printf("Please upload it and post it under that issue:");
		printf("https://github.com/xfwcfw/kelftool/issues/1");
		return KELF_ERROR_UNSUPPORTED_FILE;
	}

	std::string HeaderSignature;
	HeaderSignature.resize(8);
	fread(HeaderSignature.data(), 1, HeaderSignature.size(), f);

	if (HeaderSignature != GetHeaderSignature(header))
		return KELF_ERROR_INVALID_HEADER_SIGNATURE;

	std::string KEK = DeriveKeyEncryptionKey(header);

	Kbit.resize(16);
	fread(Kbit.data(), 1, Kbit.size(), f);

	Kc.resize(16);
	fread(Kc.data(), 1, Kc.size(), f);

	DecryptKeys(KEK);

	int BitTableSize = header.HeaderSize - ftell(f) - 8 - 8;
	if (BitTableSize > sizeof(BitTable))
		return KELF_ERROR_INVALID_BIT_TABLE_SIZE;

	fread(&bitTable, 1, BitTableSize, f);

	TdesCbcCfb64Decrypt((uint8_t *)& bitTable, (uint8_t*)& bitTable, BitTableSize, (uint8_t*)Kbit.data(), 2, ks.GetContentTableIV().data());

	std::string BitTableSignature;
	BitTableSignature.resize(8);
	fread(BitTableSignature.data(), 1, BitTableSignature.size(), f);

	if (BitTableSignature != GetBitTableSignature())
		return KELF_ERROR_INVALID_BIT_TABLE_SIGNATURE;

	std::string RootSignature;
	RootSignature.resize(8);
	fread(RootSignature.data(), 1, RootSignature.size(), f);

	if (RootSignature != GetRootSignature(HeaderSignature, BitTableSignature))
		return KELF_ERROR_INVALID_ROOT_SIGNATURE;

	for (int i = 0; i < bitTable.BlockCount; i++)
	{
		std::string Block;
		Block.resize(bitTable.Blocks[i].Size);
		fread(Block.data(), 1, Block.size(), f);
		Content += Block;
	}

	DecryptContent(header.Flags >> 4 & 3);

	if (VerifyContentSignature() != 0)
		return KELF_ERROR_INVALID_CONTENT_SIGNATURE;

	fclose(f);

	return 0;
}

int Kelf::SaveKelf(std::string filename)
{
	FILE* f = fopen(filename.c_str(), "wb");

	KELFHeader header;
	static uint8_t PSX_USER[] = { 0x01, 0x03, 0x00, 0x04, 0x00, 0x02, 0x00, 0x4A, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x01, 0x78 };
	memcpy(header.UserDefined, PSX_USER, 16);
	header.ContentSize = Content.size();
	header.HeaderSize = sizeof(KELFHeader) + 8 + 16 + 16 + 8 + 16 + 16 + 8 + 8; // header + header signature + kbit + kc + bittable + bittable signature + root signature
	header.unk = 0x0101; // PSX
	header.Flags = 0x22C; // PSX
	header.BitCount = 0;
	header.MGZones = 1; // Japan

	std::string HeaderSignature = GetHeaderSignature(header);
	std::string BitTableSignature = GetBitTableSignature();
	std::string RootSignature = GetRootSignature(HeaderSignature, BitTableSignature);

	int BitTableSize = (bitTable.BlockCount * 2 + 1) * 8;

	TdesCbcCfb64Encrypt((uint8_t*)& bitTable, (uint8_t*)& bitTable, (bitTable.BlockCount * 2 + 1) * 8, (uint8_t*)Kbit.data(), 2, ks.GetContentTableIV().data());

	std::string KEK = DeriveKeyEncryptionKey(header);
	EncryptKeys(KEK);

	fwrite(&header, sizeof(header), 1, f);
	fwrite(HeaderSignature.data(), 1, HeaderSignature.size(), f);
	fwrite(Kbit.data(), 1, Kbit.size(), f);
	fwrite(Kc.data(), 1, Kc.size(), f);
	fwrite(&bitTable, 1, BitTableSize, f);
	fwrite(BitTableSignature.data(), 1, BitTableSignature.size(), f);
	fwrite(RootSignature.data(), 1, RootSignature.size(), f);

	fwrite(Content.data(), 1, Content.size(), f);
	fclose(f);

	return 0;
}

int Kelf::LoadContent(std::string filename)
{
	FILE* f = fopen(filename.c_str(), "rb");
	fseek(f, 0, SEEK_END);
	Content.resize(ftell(f));
	fseek(f, 0, SEEK_SET);
	fread(Content.data(), 1, Content.size(), f);
	fclose(f);

	// TODO: random kbit?
	Kbit.resize(16);
	memset(Kbit.data(), 0xAA, Kbit.size());

	// TODO: random kc?
	Kc.resize(16);
	memset(Kc.data(), 0xBB, Kc.size());

	bitTable.HeaderSize = sizeof(KELFHeader) + 8 + 16 + 16 + 8 + 16 + 16 + 8 + 8; // header + header signature + kbit + kc + bittable + bittable signature + root signature
	bitTable.BlockCount = 2;
	bitTable.Blocks[0].Size = 0x20;
	bitTable.Blocks[0].Flags = BIT_BLOCK_SIGNED | BIT_BLOCK_ENCRYPTED;
	memset(bitTable.Blocks[0].Signature, 0, 8);

	// Sign
	for (int j = 0; j < 0x20; j += 8)
		xor_bit(&Content.data()[j], bitTable.Blocks[0].Signature, bitTable.Blocks[0].Signature, 8);

	uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
	memcpy(MG_SIG_MASTER_AND_HASH_KEY, ks.GetSignatureMasterKey().data(), 8);
	memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, ks.GetSignatureHashKey().data(), 8);

	TdesCbcCfb64Encrypt(bitTable.Blocks[0].Signature, bitTable.Blocks[0].Signature, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);

	// Encrypt
	TdesCbcCfb64Encrypt(Content.data(), Content.data(), 0x20, Kc.data(), 2, ks.GetContentIV().data());

	bitTable.Blocks[1].Size = Content.size() - 0x20;
	bitTable.Blocks[1].Flags = 0;
	memset(bitTable.Blocks[1].Signature, 0, 8);

	return 0;
}

int Kelf::SaveContent(std::string filename)
{
	FILE* f = fopen(filename.c_str(), "wb");
	fwrite(Content.data(), 1, Content.size(), f);
	fclose(f);

	return 0;
}

std::string Kelf::GetHeaderSignature(KELFHeader& header)
{
	uint8_t HMasterEnc[sizeof(KELFHeader)];
	TdesCbcCfb64Encrypt(HMasterEnc, (uint8_t*)& header, sizeof(KELFHeader), ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);
	
	uint8_t Hsign[8];
	memcpy(Hsign, HMasterEnc + sizeof(HMasterEnc) - 8, 8);
	TdesCbcCfb64Decrypt(Hsign, Hsign, 8, ks.GetSignatureHashKey().data(), 1, MG_IV_NULL);
	TdesCbcCfb64Encrypt(Hsign, Hsign, 8, ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);

	return std::string((char *) Hsign, 8);
}

std::string Kelf::DeriveKeyEncryptionKey(KELFHeader& header)
{
	uint8_t* KelfHeader = (uint8_t*)& header;
	uint8_t HeaderData[8];
	xor_bit(KelfHeader, &KelfHeader[8], HeaderData, 8);

	uint8_t KEK[16];
	xor_bit(ks.GetKbitIV().data(), HeaderData, KEK, 8);
	xor_bit(ks.GetKcIV().data(), HeaderData, &KEK[8], 8);

	TdesCbcCfb64Encrypt(KEK, KEK, 8, ks.GetKbitMasterKey().data(), 2, MG_IV_NULL);
	TdesCbcCfb64Encrypt(&KEK[8], &KEK[8], 8, ks.GetKcMasterKey().data(), 2, MG_IV_NULL);

	return std::string((char*) KEK, 16);
}

void Kelf::DecryptKeys(std::string KEK)
{
	TdesCbcCfb64Decrypt((uint8_t*)Kbit.data(), (uint8_t*)Kbit.data(), 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);
	TdesCbcCfb64Decrypt((uint8_t*)Kbit.data() + 8, (uint8_t*)Kbit.data() + 8, 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);

	TdesCbcCfb64Decrypt((uint8_t*)Kc.data(), (uint8_t*)Kc.data(), 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);
	TdesCbcCfb64Decrypt((uint8_t*)Kc.data() + 8, (uint8_t*)Kc.data() + 8, 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);
}

void Kelf::EncryptKeys(std::string KEK)
{
	TdesCbcCfb64Encrypt((uint8_t*)Kbit.data(), (uint8_t*)Kbit.data(), 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);
	TdesCbcCfb64Encrypt((uint8_t*)Kbit.data() + 8, (uint8_t*)Kbit.data() + 8, 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);

	TdesCbcCfb64Encrypt((uint8_t*)Kc.data(), (uint8_t*)Kc.data(), 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);
	TdesCbcCfb64Encrypt((uint8_t*)Kc.data() + 8, (uint8_t*)Kc.data() + 8, 8, (uint8_t*)KEK.data(), 2, MG_IV_NULL);
}

std::string Kelf::GetBitTableSignature()
{
	uint8_t hash[8];
	memcpy(hash, &Kbit[0], 8);
	if (memcmp(&Kbit[0], &Kbit[8], 8) != 0)
		xor_bit(&Kbit[8], hash, hash, 8);

	xor_bit(&Kc[0], hash, hash, 8);
	if (memcmp(&Kc[0], &Kc[8], 8) != 0)
		xor_bit(&Kc[8], hash, hash, 8);

	for (int i = 0; i < bitTable.BlockCount * 2 + 1; i++)
		xor_bit(&((uint8_t*)& bitTable)[i * 8], hash, hash, 8);

	uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
	memcpy(MG_SIG_MASTER_AND_HASH_KEY, ks.GetSignatureMasterKey().data(), 8);
	memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, ks.GetSignatureHashKey().data(), 8);

	uint8_t signature[8];
	TdesCbcCfb64Encrypt(signature, hash, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);

	return std::string((char*)signature, 8);
}

std::string Kelf::GetRootSignature(std::string HeaderSignature, std::string BitTableSignature)
{
	std::string Signatures;
	Signatures += HeaderSignature;
	Signatures += BitTableSignature;

	for (int i = 0; i < bitTable.BlockCount; i++)
		if (bitTable.Blocks[i].Flags & BIT_BLOCK_SIGNED)
			Signatures += std::string((char *) bitTable.Blocks[i].Signature, 8);

	TdesCbcCfb64Encrypt((uint8_t*) Signatures.data(), (uint8_t*)Signatures.data(), Signatures.size(), ks.GetRootSignatureMasterKey().data(), 1, MG_IV_NULL);
	std::string Root;
	Root.resize(8);
	TdesCbcCfb64Decrypt((uint8_t*)Root.data(), (uint8_t*)Signatures.substr(Signatures.size() - 8).data(), 8, ks.GetRootSignatureHashKey().data(), 2, MG_IV_NULL);

	return Root;
}

void Kelf::DecryptContent(int keycount)
{
	uint32_t offset = 0;
	for (int i = 0; i < bitTable.BlockCount; i++)
	{
		if (bitTable.Blocks[i].Flags & BIT_BLOCK_ENCRYPTED)
			TdesCbcCfb64Decrypt(&Content.data()[offset], &Content.data()[offset], bitTable.Blocks[i].Size, Kc.data(), keycount, ks.GetContentIV().data());
		offset += bitTable.Blocks[i].Size;
	}
}

int Kelf::VerifyContentSignature()
{
	uint32_t offset = 0;
	for (int i = 0; i < bitTable.BlockCount; i++)
	{
		if (bitTable.Blocks[i].Flags & BIT_BLOCK_SIGNED)
		{
			uint8_t signature[8];
			memset(signature, 0, 8);

			if (bitTable.Blocks[i].Flags & BIT_BLOCK_ENCRYPTED)
			{
				for (int j = 0; j < bitTable.Blocks[i].Size; j += 8)
					xor_bit(&Content.data()[offset + j], signature, signature, 8);

				uint8_t MG_SIG_MASTER_AND_HASH_KEY[16];
				memcpy(MG_SIG_MASTER_AND_HASH_KEY, ks.GetSignatureMasterKey().data(), 8);
				memcpy(MG_SIG_MASTER_AND_HASH_KEY + 8, ks.GetSignatureHashKey().data(), 8);

				TdesCbcCfb64Encrypt(signature, signature, 8, MG_SIG_MASTER_AND_HASH_KEY, 2, MG_IV_NULL);
			}
			else
			{
				std::string SigMasterEnc;
				SigMasterEnc.resize(bitTable.Blocks[i].Size);
				TdesCbcCfb64Encrypt(SigMasterEnc.data(), &Content.data()[offset], bitTable.Blocks[i].Size, ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);
				memcpy(signature, &SigMasterEnc.data()[bitTable.Blocks[i].Size - 8], 8);
				TdesCbcCfb64Decrypt(signature, signature, 8, ks.GetSignatureHashKey().data(), 1, MG_IV_NULL);
				TdesCbcCfb64Encrypt(signature, signature, 8, ks.GetSignatureMasterKey().data(), 1, MG_IV_NULL);
			}

			if (memcmp(bitTable.Blocks[i].Signature, signature, 8) != 0)
				return KELF_ERROR_INVALID_CONTENT_SIGNATURE;
		}

		offset += bitTable.Blocks[i].Size;
	}

	return 0;
}
