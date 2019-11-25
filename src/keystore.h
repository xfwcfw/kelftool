/*
 * Copyright (c) 2019 xfwcfw
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __KEYSTORE_H__
#define __KEYSTORE_H__

#include <string>

#define KEYSTORE_ERROR_OPEN_FAILED -1
#define KEYSTORE_ERROR_LINE_NOT_KEY_VALUE -2
#define KEYSTORE_ERROR_ODD_LEN_VALUE -3
#define KEYSTORE_ERROR_MISSING_KEY -4

class KeyStore
{
	std::string SignatureMasterKey;
	std::string SignatureHashKey;
	std::string KbitMasterKey;
	std::string KbitIV;
	std::string KcMasterKey;
	std::string KcIV;
	std::string RootSignatureMasterKey;
	std::string RootSignatureHashKey;
	std::string ContentTableIV;
	std::string ContentIV;

public:
	int Load(std::string filename);

	std::string GetSignatureMasterKey() { return SignatureMasterKey; }
	std::string GetSignatureHashKey() { return SignatureHashKey; }
	std::string GetKbitMasterKey() { return KbitMasterKey; }
	std::string GetKbitIV() { return KbitIV; }
	std::string GetKcMasterKey() { return KcMasterKey; }
	std::string GetKcIV() { return KcIV; }
	std::string GetRootSignatureMasterKey() { return RootSignatureMasterKey; }
	std::string GetRootSignatureHashKey() { return RootSignatureHashKey; }
	std::string GetContentTableIV() { return ContentTableIV; }
	std::string GetContentIV() { return ContentIV; }

	static std::string getErrorString(int err);
};

#endif