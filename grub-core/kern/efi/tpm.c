#include <grub/err.h>
#include <grub/i18n.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/efi/tpm.h>
#include <grub/mm.h>
#include <grub/tpm.h>
#include <grub/term.h>

//#define TPM_DEBUG_DUMP

static grub_err_t grub_tpm2_start_auth_session(TPMI_ALG_HASH sessionHashAlgo,
    TPMI_SH_AUTH_SESSION *sessionHandle, TPM2B_NONCE *nonceTPM);
static grub_err_t grub_tpm2_policy_pcr(TPMI_SH_POLICY sessionHandle,
    const grub_uint8_t pcrSelect[PCR_SELECT_MAX]);
static grub_err_t grub_tpm2_nv_read(TPMI_SH_AUTH_SESSION sessionHandle,
    TPMI_RH_NV_INDEX nvIndex, grub_uint16_t size, grub_uint16_t offset,
    grub_uint8_t *buf);
grub_err_t grub_tpm2_read_pcrs(const grub_uint8_t pcrSelect[PCR_SELECT_MAX]);
static grub_err_t grub_tpm2_get_random(grub_uint16_t bytesRequested,
    grub_uint8_t *result);
static void grub_tpm_alloc_param_blocks(grub_uint16_t cmdSize,
    grub_uint16_t respSize, PassThroughToTPM_InputParamBlock **inbuf,
    PassThroughToTPM_OutputParamBlock **outbuf);
static void grub_tpm_free_param_blocks(PassThroughToTPM_InputParamBlock **inbuf,
    PassThroughToTPM_OutputParamBlock **outbuf);
static grub_err_t grub_tpm2_command(PassThroughToTPM_InputParamBlock *inbuf,
    PassThroughToTPM_OutputParamBlock *outbuf);
static void printCommand(const PassThroughToTPM_InputParamBlock *inbuf);
static void printResponse(const PassThroughToTPM_OutputParamBlock *outbuf);
#ifdef TMP_DEBUG_DUMP
static void printPassThroughBuffer(grub_uint16_t bufsiz, const grub_uint8_t *buf);
#endif

static grub_efi_guid_t tpm_guid = EFI_TPM_GUID;
static grub_efi_guid_t tpm2_guid = EFI_TPM2_GUID;

static grub_efi_boolean_t grub_tpm_present(grub_efi_tpm_protocol_t *tpm)
{
  grub_efi_status_t status;
  TCG_EFI_BOOT_SERVICE_CAPABILITY caps;
  grub_uint32_t flags;
  grub_efi_physical_address_t eventlog, lastevent;

  caps.Size = (grub_uint8_t)sizeof(caps);

  status = efi_call_5(tpm->status_check, tpm, &caps, &flags, &eventlog,
		      &lastevent);

  if (status != GRUB_EFI_SUCCESS || caps.TPMDeactivatedFlag
      || !caps.TPMPresentFlag)
    return 0;

  return 1;
}

static grub_efi_boolean_t grub_tpm2_present(grub_efi_tpm2_protocol_t *tpm)
{
  grub_efi_status_t status;
  EFI_TCG2_BOOT_SERVICE_CAPABILITY caps;

  caps.Size = (grub_uint8_t)sizeof(caps);

  status = efi_call_2(tpm->get_capability, tpm, &caps);

  if (status != GRUB_EFI_SUCCESS || !caps.TPMPresentFlag)
    return 0;

  return 1;
}

static grub_efi_boolean_t grub_tpm_handle_find(grub_efi_handle_t *tpm_handle,
					       grub_efi_uint8_t *protocol_version)
{
  grub_efi_handle_t *handles;
  grub_efi_uintn_t num_handles;

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &tpm_guid, NULL,
				    &num_handles);
  if (handles && num_handles > 0) {
    *tpm_handle = handles[0];
    *protocol_version = 1;
    return 1;
  }

  handles = grub_efi_locate_handle (GRUB_EFI_BY_PROTOCOL, &tpm2_guid, NULL,
				    &num_handles);
  if (handles && num_handles > 0) {
    *tpm_handle = handles[0];
    *protocol_version = 2;
    return 1;
  }

  return 0;
}

static grub_err_t
grub_tpm1_execute(grub_efi_handle_t tpm_handle,
		  PassThroughToTPM_InputParamBlock *inbuf,
		  PassThroughToTPM_OutputParamBlock *outbuf)
{
  grub_efi_status_t status;
  grub_efi_tpm_protocol_t *tpm;
  grub_uint32_t inhdrsize = sizeof(*inbuf) - sizeof(inbuf->TPMOperandIn);
  grub_uint32_t outhdrsize = sizeof(*outbuf) - sizeof(outbuf->TPMOperandOut);

  tpm = grub_efi_open_protocol (tpm_handle, &tpm_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm_present(tpm))
    return 0;

  /* UEFI TPM protocol takes the raw operand block, no param block header */
  status = efi_call_5 (tpm->pass_through_to_tpm, tpm,
		       inbuf->IPBLength - inhdrsize, inbuf->TPMOperandIn,
		       outbuf->OPBLength - outhdrsize, outbuf->TPMOperandOut);

  switch (status) {
  case GRUB_EFI_SUCCESS:
    return 0;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
  case GRUB_EFI_NOT_FOUND:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }
}

static grub_err_t
grub_tpm2_execute(grub_efi_handle_t tpm_handle,
		  PassThroughToTPM_InputParamBlock *inbuf,
		  PassThroughToTPM_OutputParamBlock *outbuf)
{
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *tpm;
  grub_uint32_t inhdrsize = sizeof(*inbuf) - sizeof(inbuf->TPMOperandIn);
  grub_uint32_t outhdrsize = sizeof(*outbuf) - sizeof(outbuf->TPMOperandOut);

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm2_present(tpm))
    return 0;

  /* UEFI TPM protocol takes the raw operand block, no param block header */
  status = efi_call_5 (tpm->submit_command, tpm,
		       inbuf->IPBLength - inhdrsize, inbuf->TPMOperandIn,
		       outbuf->OPBLength - outhdrsize, outbuf->TPMOperandOut);

  switch (status) {
  case GRUB_EFI_SUCCESS:
    return 0;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
  case GRUB_EFI_NOT_FOUND:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }
}

grub_err_t
grub_tpm_execute(PassThroughToTPM_InputParamBlock *inbuf,
		 PassThroughToTPM_OutputParamBlock *outbuf)
{
  grub_efi_handle_t tpm_handle;
   grub_uint8_t protocol_version;

  /* It's not a hard failure for there to be no TPM */
  if (!grub_tpm_handle_find(&tpm_handle, &protocol_version))
    return 0;

  if (protocol_version == 1) {
    return grub_tpm1_execute(tpm_handle, inbuf, outbuf);
  } else {
    return grub_tpm2_execute(tpm_handle, inbuf, outbuf);
  }
}

static grub_err_t
grub_tpm1_log_event(grub_efi_handle_t tpm_handle, unsigned char *buf,
		    grub_size_t size, grub_uint8_t pcr,
		    const char *description)
{
  TCG_PCR_EVENT *event;
  grub_efi_status_t status;
  grub_efi_tpm_protocol_t *tpm;
  grub_efi_physical_address_t lastevent;
  grub_uint32_t algorithm;
  grub_uint32_t eventnum = 0;

  tpm = grub_efi_open_protocol (tpm_handle, &tpm_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm_present(tpm))
    return 0;

  event = grub_zalloc(sizeof (TCG_PCR_EVENT) + grub_strlen(description) + 1);
  if (!event)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("cannot allocate TPM event buffer"));

  event->PCRIndex  = pcr;
  event->EventType = EV_IPL;
  event->EventSize = grub_strlen(description) + 1;
  grub_memcpy(event->Event, description, event->EventSize);

  algorithm = TCG_ALG_SHA;
  status = efi_call_7 (tpm->log_extend_event, tpm, (grub_efi_physical_address_t)buf, (grub_uint64_t) size,
		       algorithm, event, &eventnum, &lastevent);

  switch (status) {
  case GRUB_EFI_SUCCESS:
    return 0;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
  case GRUB_EFI_NOT_FOUND:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }
}

static grub_err_t
grub_tpm2_log_event(grub_efi_handle_t tpm_handle, unsigned char *buf,
		   grub_size_t size, grub_uint8_t pcr,
		   const char *description)
{
  EFI_TCG2_EVENT *event;
  grub_efi_status_t status;
  grub_efi_tpm2_protocol_t *tpm;

  tpm = grub_efi_open_protocol (tpm_handle, &tpm2_guid,
				GRUB_EFI_OPEN_PROTOCOL_GET_PROTOCOL);

  if (!grub_tpm2_present(tpm))
    return 0;

  event = grub_zalloc(sizeof (EFI_TCG2_EVENT) + grub_strlen(description) + 1);
  if (!event)
    return grub_error (GRUB_ERR_OUT_OF_MEMORY,
		       N_("cannot allocate TPM event buffer"));

  event->Header.HeaderSize = sizeof(EFI_TCG2_EVENT_HEADER);
  event->Header.HeaderVersion = 1;
  event->Header.PCRIndex = pcr;
  event->Header.EventType = EV_IPL;
  event->Size = sizeof(*event) - sizeof(event->Event) + grub_strlen(description) + 1;
  grub_memcpy(event->Event, description, grub_strlen(description) + 1);

  status = efi_call_5 (tpm->hash_log_extend_event, tpm, 0, (grub_efi_physical_address_t)buf,
		       (grub_uint64_t) size, event);

  switch (status) {
  case GRUB_EFI_SUCCESS:
    return 0;
  case GRUB_EFI_DEVICE_ERROR:
    return grub_error (GRUB_ERR_IO, N_("Command failed"));
  case GRUB_EFI_INVALID_PARAMETER:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Invalid parameter"));
  case GRUB_EFI_BUFFER_TOO_SMALL:
    return grub_error (GRUB_ERR_BAD_ARGUMENT, N_("Output buffer too small"));
  case GRUB_EFI_NOT_FOUND:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("TPM unavailable"));
  default:
    return grub_error (GRUB_ERR_UNKNOWN_DEVICE, N_("Unknown TPM error"));
  }
}

grub_err_t
grub_tpm_log_event(unsigned char *buf, grub_size_t size, grub_uint8_t pcr,
		   const char *description)
{
  grub_efi_handle_t tpm_handle;
  grub_efi_uint8_t protocol_version;

  if (!grub_tpm_handle_find(&tpm_handle, &protocol_version))
    return 0;

  if (protocol_version == 1) {
    return grub_tpm1_log_event(tpm_handle, buf, size, pcr, description);
  } else {
    return grub_tpm2_log_event(tpm_handle, buf, size, pcr, description);
  }
}

static grub_err_t
grub_tpm2_nvread_pcr_policy(grub_uint8_t pcrSelect[PCR_SELECT_MAX], 
      grub_uint32_t nvIndex, grub_uint16_t bufsiz, grub_uint8_t *buf)
{
  TPMI_SH_AUTH_SESSION authSessionHandle = 0;
  TPM2B_NONCE authSessionNonce;
  grub_err_t err;

  err = grub_tpm2_start_auth_session(TPM_ALG_SHA256, &authSessionHandle, &authSessionNonce);
  if (err != GRUB_ERR_NONE)
    return err;

  err = grub_tpm2_policy_pcr(authSessionHandle, pcrSelect);
  if (err != GRUB_ERR_NONE)
    return err;

  err = grub_tpm2_nv_read(authSessionHandle, nvIndex, bufsiz, 0, buf);
  if (err != GRUB_ERR_NONE)
    return err;

  return err;
}

grub_err_t
grub_tpm_nvread_pcr_policy(grub_uint8_t pcrSelect[PCR_SELECT_MAX], 
      grub_uint32_t nvIndex, grub_uint16_t bufsiz, grub_uint8_t *buf)
{
  grub_efi_handle_t tpm_handle;
  grub_efi_uint8_t protocol_version;

  if (!grub_tpm_handle_find(&tpm_handle, &protocol_version))
    return 0;

  if (protocol_version == 2)
    return grub_tpm2_nvread_pcr_policy(pcrSelect, nvIndex, bufsiz, buf);

  return 0;
}

/* TODO - add a comment on the marshalling madness */

#define TPM2_NONCE_SIZE SHA1_DIGEST_SIZE

typedef struct
{
  TPM_ST tag;
  grub_uint32_t commandSize;
  TPM_CC commandCode;
} GRUB_PACKED CommandHeader;

typedef struct
{
  TPM_ST        tag;
  grub_uint32_t responseSize;
  TPM_RC        responseCode;
} GRUB_PACKED ResponseHeader;

typedef struct
{
  grub_uint16_t size;
  grub_uint8_t buffer[SHA1_DIGEST_SIZE];
} GRUB_PACKED BufferSha1;

typedef struct
{
  grub_uint16_t size;
  grub_uint8_t buffer[SHA256_DIGEST_SIZE];
} GRUB_PACKED BufferSha256;

typedef struct
{
  grub_uint16_t size;
} GRUB_PACKED BufferEmpty;

typedef struct
{
  CommandHeader hdr;
  TPMI_DH_OBJECT tpmKey;
  TPMI_DH_ENTITY bind;
  /* TPM2B_NONCE */
  struct
  {
    grub_uint16_t size;
    grub_uint8_t buffer[TPM2_NONCE_SIZE];
  } GRUB_PACKED nonceCaller;
  /* TPM2B_ENCRYPTED_SECRET */
  struct
  {
    grub_uint16_t size;
  } GRUB_PACKED encryptedSalt;
  TPM_SE sessionType;
  /* TPMT_SYM_DEF */
  struct
  {
    TPMI_ALG_SYM algorithm;
  } GRUB_PACKED symmetric;
  TPMI_ALG_HASH authHash;
} GRUB_PACKED StartAuthSessionCommand;

// TODO - there's not actually a nonce in the response (size 0)
typedef struct
{
  ResponseHeader hdr;
  TPMI_SH_AUTH_SESSION  sessionHandle;
  TPM2B_NONCE           nonceTPM;
} GRUB_PACKED StartAuthSessionResponse;

static grub_err_t
grub_tpm2_start_auth_session(TPMI_ALG_HASH sessionHashAlgo, TPMI_SH_AUTH_SESSION *sessionHandle,
    TPM2B_NONCE *nonceTPM)
{
  grub_err_t err;
  PassThroughToTPM_InputParamBlock *inbuf;
  PassThroughToTPM_OutputParamBlock *outbuf;
  StartAuthSessionCommand *cmd;
  StartAuthSessionResponse *resp;

  grub_tpm_alloc_param_blocks(sizeof(*cmd), sizeof(*resp), &inbuf, &outbuf);
  cmd = (StartAuthSessionCommand *)inbuf->TPMOperandIn;
  resp = (StartAuthSessionResponse *)outbuf->TPMOperandOut;

  cmd = (StartAuthSessionCommand *)inbuf->TPMOperandIn;
  cmd->hdr.tag = grub_swap_bytes16(TPM_ST_NO_SESSIONS);
  cmd->hdr.commandSize = grub_swap_bytes32(sizeof(*cmd));
  cmd->hdr.commandCode = grub_swap_bytes32(TPM_CC_StartAuthSession);
  cmd->tpmKey = grub_swap_bytes32(TPM_RH_NULL);
  cmd->bind = grub_swap_bytes32(TPM_RH_NULL);
  cmd->nonceCaller.size = grub_swap_bytes16(TPM2_NONCE_SIZE);
  err = grub_tpm2_get_random(TPM2_NONCE_SIZE, cmd->nonceCaller.buffer);
  if (err != GRUB_ERR_NONE)
    goto exit;
  cmd->encryptedSalt.size = 0;
	cmd->sessionType = TPM_SE_POLICY;
  cmd->symmetric.algorithm = grub_swap_bytes16(TPM_ALG_NULL);
  cmd->authHash = grub_swap_bytes16(sessionHashAlgo);

  err = grub_tpm2_command(inbuf, outbuf);
  if (err == GRUB_ERR_NONE)
  {
    *sessionHandle = grub_swap_bytes32(resp->sessionHandle);
    nonceTPM->size = grub_swap_bytes16(resp->nonceTPM.size);
    grub_memcpy(nonceTPM->buffer, resp->nonceTPM.buffer, nonceTPM->size);
  }

exit:
  grub_tpm_free_param_blocks(&inbuf, &outbuf);
  return err;
}

typedef struct
{
  CommandHeader hdr;
  /* TPML_PCR_SELECTION */
  struct
  {
    grub_uint32_t count;
    TPMS_PCR_SELECTION pcrSelections[1];
  } GRUB_PACKED pcrSelectIn;
} GRUB_PACKED PCRReadCommand;

typedef struct
{
  ResponseHeader hdr;
  grub_uint32_t pcrUpdateCounter;
  /* TPML_PCR_SELECTION */
  struct
  {
    grub_uint32_t count; /* Should be 1 */
    TPMS_PCR_SELECTION pcrSelections[1];
  } GRUB_PACKED pcrSelectionOut;
  /* TPML_DIGEST */
  struct
  {
    grub_uint32_t count;
    BufferSha1 digests[1]; /* variable sized - up to 8 entries */
  } GRUB_PACKED pcrValues;
} GRUB_PACKED PCRReadResponse;

typedef struct
{
  CommandHeader hdr;
  TPMI_SH_POLICY sessionHandle;
  /* TPM2B_DIGEST */
  BufferEmpty pcrDigest;
  /* TPML_PCR_SELECTION */
  struct
  {
    grub_uint32_t count;
    TPMS_PCR_SELECTION pcrSelections[1];
  } GRUB_PACKED pcrs;
} GRUB_PACKED PolicyPcrCommand;

typedef struct
{
  ResponseHeader hdr;
} GRUB_PACKED PolicyPcrResponse;

static grub_err_t
grub_tpm2_policy_pcr(TPMI_SH_POLICY sessionHandle, const grub_uint8_t pcrSelect[PCR_SELECT_MAX])
{
  PassThroughToTPM_InputParamBlock *inbuf;
  PassThroughToTPM_OutputParamBlock *outbuf;
  PolicyPcrCommand *cmd;
  PolicyPcrResponse *resp;

  grub_tpm_alloc_param_blocks(sizeof(*cmd), sizeof(*resp), &inbuf, &outbuf);
  cmd = (PolicyPcrCommand *)inbuf->TPMOperandIn;
  resp = (PolicyPcrResponse *)outbuf->TPMOperandOut;

  cmd->hdr.tag = grub_swap_bytes16(TPM_ST_NO_SESSIONS);
  cmd->hdr.commandSize = grub_swap_bytes32(sizeof(*cmd));
  cmd->hdr.commandCode = grub_swap_bytes32(TPM_CC_PolicyPCR);
  cmd->sessionHandle = grub_swap_bytes32(sessionHandle);
  cmd->pcrDigest.size = 0;
  cmd->pcrs.count = grub_swap_bytes32(1);
  cmd->pcrs.pcrSelections[0].hash = grub_swap_bytes16(TPM_ALG_SHA1);
  cmd->pcrs.pcrSelections[0].sizeofSelect = PCR_SELECT_MAX;
  cmd->pcrs.pcrSelections[0].pcrSelect[0] = pcrSelect[0];
  cmd->pcrs.pcrSelections[0].pcrSelect[1] = pcrSelect[1];
  cmd->pcrs.pcrSelections[0].pcrSelect[2] = pcrSelect[2];

  grub_err_t err = grub_tpm2_command(inbuf, outbuf);

  grub_tpm_free_param_blocks(&inbuf, &outbuf);

  return err;
}

typedef struct
{
  CommandHeader hdr;
  TPMI_RH_NV_AUTH authHandle;
  TPMI_RH_NV_INDEX nvIndex;
  grub_uint32_t authSize;
  /* TPMS_AUTH_COMMAND */
  struct
  {
    TPMI_SH_AUTH_SESSION  sessionHandle;
    BufferEmpty nonce;
    TPMA_SESSION sessionAttributes;
    BufferEmpty hmac;
  } GRUB_PACKED auth;
  grub_uint16_t size;
  grub_uint16_t offset;
} GRUB_PACKED NvReadCommand;

typedef struct
{
  ResponseHeader hdr;
  grub_uint32_t authSize;
  TPM2B_MAX_NV_BUFFER buffer;
  /* TPMS_AUTH_RESPONSE  - we don't care */
} GRUB_PACKED NvReadResponse;

static grub_err_t
grub_tpm2_nv_read(TPMI_SH_AUTH_SESSION sessionHandle, TPMI_RH_NV_INDEX nvIndex,
    grub_uint16_t size, grub_uint16_t offset, grub_uint8_t *buf)
{
  PassThroughToTPM_InputParamBlock *inbuf;
  PassThroughToTPM_OutputParamBlock *outbuf;
  NvReadCommand *cmd;
  NvReadResponse *resp;

  grub_tpm_alloc_param_blocks(sizeof(*cmd), sizeof(*resp), &inbuf, &outbuf);
  cmd = (NvReadCommand *)inbuf->TPMOperandIn;
  resp = (NvReadResponse *)outbuf->TPMOperandOut;

  cmd->hdr.tag = grub_swap_bytes16(TPM_ST_SESSIONS);
  cmd->hdr.commandSize = grub_swap_bytes32(sizeof(*cmd));
  cmd->hdr.commandCode = grub_swap_bytes32(TPM_CC_NV_Read);
  cmd->authHandle = grub_swap_bytes32(nvIndex);
  cmd->nvIndex = grub_swap_bytes32(nvIndex);
  cmd->authSize = grub_swap_bytes32(sizeof(cmd->auth));
  cmd->auth.sessionHandle = grub_swap_bytes32(sessionHandle);
  cmd->auth.nonce.size = 0;
  /* Note that we don't set continueSession. This means the sessionHandle is now
   * unusable for anything else, and also we don't need a FlushContext to clean up */
  cmd->auth.sessionAttributes.val = 0;
  cmd->auth.hmac.size = 0;
  cmd->size = grub_swap_bytes16(size);
  cmd->offset = grub_swap_bytes16(offset);

  grub_err_t err = grub_tpm2_command(inbuf, outbuf);
  if (err == GRUB_ERR_NONE)
  {
    grub_uint16_t readSize = grub_swap_bytes16(resp->buffer.size);
    if (readSize != size)
      err = grub_error(GRUB_ERR_UNKNOWN_DEVICE, "Invalid response size. Expected: %u got %u", size, readSize);
    else
      grub_memcpy(buf, resp->buffer.buffer, readSize);
  }

  grub_tpm_free_param_blocks(&inbuf, &outbuf);
  return err;
}

typedef struct
{
  CommandHeader hdr;
  grub_uint16_t bytesRequested;
} GRUB_PACKED GetRandomCommand;

typedef struct
{
  ResponseHeader hdr;
  TPM2B_DIGEST  randomBytes;
} GRUB_PACKED GetRandomResponse;

static grub_err_t
grub_tpm2_get_random(grub_uint16_t bytesRequested, grub_uint8_t *result)
{
  if (bytesRequested > sizeof(TPMU_HA))
		return grub_error (GRUB_ERR_BAD_ARGUMENT, "Too many random bytes requested");

  PassThroughToTPM_InputParamBlock *inbuf;
  PassThroughToTPM_OutputParamBlock *outbuf;
  GetRandomCommand *cmd;
  GetRandomResponse *resp;

  grub_tpm_alloc_param_blocks(sizeof(*cmd), sizeof(*resp), &inbuf, &outbuf);
  cmd = (GetRandomCommand *)inbuf->TPMOperandIn;
  resp = (GetRandomResponse *)outbuf->TPMOperandOut;

  cmd->hdr.tag = grub_swap_bytes16_compile_time(TPM_ST_NO_SESSIONS);
  cmd->hdr.commandSize = grub_swap_bytes32(sizeof(*cmd));
  cmd->hdr.commandCode = grub_swap_bytes32_compile_time(TPM_CC_GetRandom);
  cmd->bytesRequested = grub_swap_bytes16(bytesRequested);

  grub_err_t err = grub_tpm2_command(inbuf, outbuf);
  if (err == GRUB_ERR_NONE)
  {
    if (grub_swap_bytes16(resp->randomBytes.size) == bytesRequested)
		{
			grub_memcpy(result, resp->randomBytes.buffer, bytesRequested);
    }
    else
	  {
			err = grub_error(GRUB_ERR_UNKNOWN_DEVICE, "Invalid response size. Expected %u got %u\n",
				 bytesRequested, grub_swap_bytes16(resp->randomBytes.size));
		}
  }

	return err;
}

/* This is just here for debugging really... */
grub_err_t
grub_tpm2_read_pcrs(const grub_uint8_t pcrSelect[PCR_SELECT_MAX])
{
  /* Read the PCR values */

  unsigned int i, j;
  int npcrs = 0;
  for (i = 0; i < PCR_SELECT_MAX; i++)
  {
    for (j = 0; j < 8; j++)
      if (pcrSelect[i] & (1 << j))
        npcrs++;
  }

  grub_err_t err;

  PassThroughToTPM_InputParamBlock *inbuf;
  PassThroughToTPM_OutputParamBlock *outbuf;
  PCRReadCommand *cmd;
  PCRReadResponse *resp;

  grub_tpm_alloc_param_blocks(sizeof(*cmd), sizeof(*resp) + sizeof(BufferSha1) * (npcrs-1) , &inbuf, &outbuf);
  cmd = (PCRReadCommand *)inbuf->TPMOperandIn;
  resp = (PCRReadResponse *)outbuf->TPMOperandOut;

  cmd->hdr.tag = grub_swap_bytes16(TPM_ST_NO_SESSIONS);
  cmd->hdr.commandSize = grub_swap_bytes32(sizeof(*cmd));
  cmd->hdr.commandCode = grub_swap_bytes32(TPM_CC_PCR_Read);
  cmd->pcrSelectIn.count = grub_swap_bytes32(1);
  cmd->pcrSelectIn.pcrSelections[0].hash = grub_swap_bytes16(TPM_ALG_SHA1);
  cmd->pcrSelectIn.pcrSelections[0].sizeofSelect = PCR_SELECT_MAX;
  cmd->pcrSelectIn.pcrSelections[0].pcrSelect[0] = pcrSelect[0];
  cmd->pcrSelectIn.pcrSelections[0].pcrSelect[1] = pcrSelect[1];
  cmd->pcrSelectIn.pcrSelections[0].pcrSelect[2] = pcrSelect[2];

  unsigned int nDigests;

  err = grub_tpm2_command(inbuf, outbuf);
  if (err != GRUB_ERR_NONE)
    goto exit;

  nDigests = grub_swap_bytes32(resp->pcrValues.count);
  for (i = 0; i < nDigests; i++)
  {

    grub_printf("hash %u: ", i);
    for (j = 0; j < SHA1_DIGEST_SIZE; j++)
      grub_printf("%02x ", resp->pcrValues.digests[i].buffer[j]);
    grub_printf("\n");
  }

exit:
  grub_tpm_free_param_blocks(&inbuf, &outbuf);
  return err;
}


static void
grub_tpm_alloc_param_blocks(grub_uint16_t cmdSize, grub_uint16_t respSize,
    PassThroughToTPM_InputParamBlock **inbuf, PassThroughToTPM_OutputParamBlock **outbuf)
{
  *inbuf = NULL;
  *outbuf = NULL;

  grub_uint16_t outbufLen = sizeof(**outbuf) + respSize - sizeof((*outbuf)->TPMOperandOut);
  *outbuf = grub_zalloc(outbufLen);
  if (!*outbuf)
    grub_fatal("Failed to allocate TPM buffer");

  (*outbuf)->OPBLength = outbufLen;
  
  grub_uint16_t inbufLen = sizeof(**inbuf) + cmdSize - sizeof((*inbuf)->TPMOperandIn);
  *inbuf = grub_zalloc(inbufLen);
  if (!*inbuf)
    grub_fatal("Failed to allocate TPM buffer");

  (*inbuf)->IPBLength = inbufLen;
  (*inbuf)->OPBLength = outbufLen;
}

static void
grub_tpm_free_param_blocks(PassThroughToTPM_InputParamBlock **inbuf,
    PassThroughToTPM_OutputParamBlock **outbuf)
{
  if (*inbuf)
  {
    grub_memset(*inbuf, 0, (*inbuf)->IPBLength); /* In case it contains sensitive info */
    grub_free(*inbuf);
    *inbuf = NULL;
  }
  if (*outbuf)
  {
    grub_memset(*outbuf, 0, (*outbuf)->OPBLength); /* In case it contains sensitive info */
    grub_free(*outbuf);
    *outbuf = NULL;
  }
}

static grub_err_t
grub_tpm2_command(PassThroughToTPM_InputParamBlock *inbuf, PassThroughToTPM_OutputParamBlock *outbuf)
{
  grub_err_t err;

  const CommandHeader *cmdHdr = (CommandHeader *)inbuf->TPMOperandIn;
  const ResponseHeader *respHdr = (ResponseHeader *)outbuf->TPMOperandOut;

  printCommand(inbuf);

  err = grub_tpm_execute(inbuf, outbuf);
  if (err == GRUB_ERR_NONE)
  {
    printResponse(outbuf);
    if (respHdr->tag != cmdHdr->tag || respHdr->responseCode != TPM_RC_SUCCESS)
    {
      err = grub_error(GRUB_ERR_UNKNOWN_DEVICE, 
          "Failed to execute tpm command 0x%x. Response: tag 0x%x size %u code 0x%x",
          grub_swap_bytes32(cmdHdr->commandCode), grub_swap_bytes16(respHdr->tag),
          grub_swap_bytes32(respHdr->responseSize), grub_swap_bytes32(respHdr->responseCode));
    }
  }

  return err;
}

#ifdef TPM_DEBUG_DUMP
static void printCommand(const PassThroughToTPM_InputParamBlock *inbuf)
{
  const CommandHeader *cmdHdr = (CommandHeader *)inbuf->TPMOperandIn;
  grub_printf("Command: tag 0x%x code 0x%x\n", grub_swap_bytes16(cmdHdr->tag),
      grub_swap_bytes32(cmdHdr->commandCode));
  printPassThroughBuffer(inbuf->IPBLength - sizeof(*inbuf) + sizeof(inbuf->TPMOperandIn),
      inbuf->TPMOperandIn);

}

static void printResponse(const PassThroughToTPM_OutputParamBlock *outbuf)
{
  const ResponseHeader *respHdr = (ResponseHeader *)outbuf->TPMOperandOut;
  grub_printf("Response: tag 0x%x size %u code 0x%x\n",
          grub_swap_bytes16(respHdr->tag), grub_swap_bytes32(respHdr->responseSize),
          grub_swap_bytes32(respHdr->responseCode));
  printPassThroughBuffer(outbuf->OPBLength - sizeof(*outbuf) + sizeof(outbuf->TPMOperandOut),
      outbuf->TPMOperandOut);

}

static void printPassThroughBuffer(grub_uint16_t bufsiz, const grub_uint8_t *buf)
{
  for (unsigned int i = 0; i < bufsiz; i++)
  {
    if (i % 16 == 0)
      grub_printf("\n");
    grub_printf("%02x ", buf[i]);
  }
  grub_printf("\n");
}
#else

static void printCommand(const PassThroughToTPM_InputParamBlock *inbuf __attribute__ ((unused))) {}
static void printResponse(const PassThroughToTPM_OutputParamBlock *outbuf __attribute__ ((unused))) {}

#endif /* TPM_DEBUG_DUMP */
