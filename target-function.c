
extern OpcUa_EncodeableTypeTable OpcUa_ProxyStub_g_EncodeableTypes;
extern OpcUa_StringTable OpcUa_ProxyStub_g_NamespaceUris;


static int is_initialized = 0;

int LLVMFuzzerTestOneInput(char *pData, size_t Size)
{
    OpcUa_StatusCode uStatus;
    OpcUa_MessageContext cContext;
    OpcUa_Decoder* pDecoder;
    OpcUa_Handle hDecoderContext;
    OpcUa_InputStream* pInputStream;
    OpcUa_EncodeableType MessageType;
    OpcUa_Void *pMessage = NULL;
    OpcUa_EncodeableType * pMessageType = OpcUa_Null;
    OpcUa_UInt32 nTypeId;
    
    if (!is_initialized) {
        my_Read_ServiceType.ResponseType            = &OpcUa_ReadResponse_EncodeableType;
        my_Browse_ServiceType.ResponseType          = &OpcUa_BrowseResponse_EncodeableType;
        OTServer_ServiceGetEndpoints.ResponseType   = &OpcUa_GetEndpointsResponse_EncodeableType;
        ServiceCreateSession.ResponseType           = &OpcUa_CreateSessionResponse_EncodeableType;
        ActivateSession.ResponseType                = &OpcUa_ActivateSessionResponse_EncodeableType;
        CloseSession.ResponseType                   = &OpcUa_CloseSessionResponse_EncodeableType;
        my_BrowseNext_ServiceType.ResponseType      = &OpcUa_BrowseNextResponse_EncodeableType;
        my_FindServers_ServiceType.ResponseType     = &OpcUa_FindServersResponse_EncodeableType;
        dummy_CreateSubscription.ResponseType       = &OpcUa_CreateSubscriptionResponse_EncodeableType;
        
        /* Initialize Stack */
        uStatus = UaTestServer_Initialize();
        if(OpcUa_IsBad(uStatus))
        {
            printf("Could not initialize application!\n");
            exit(0);
        }

        uStatus = initialize_value_attribute_of_variablenodes_variabletypenodes();
        is_initialized = 1;
        printf("initialized!\n");
    }

    
    OpcUa_MessageContext_Initialize(&cContext);

    cContext.KnownTypes = &OpcUa_ProxyStub_g_EncodeableTypes;
    cContext.NamespaceUris = &OpcUa_ProxyStub_g_NamespaceUris;
    cContext.AlwaysCheckLengths = OpcUa_False;

    uStatus = OpcUa_MemoryStream_CreateReadable(pData, Size, &pInputStream);
    if (uStatus != OpcUa_Good) goto err;

    uStatus = OpcUa_BinaryDecoder_Create(&pDecoder); 
    if (uStatus != OpcUa_Good) goto err;

    uStatus = pDecoder->Open(pDecoder, pInputStream, &cContext, &hDecoderContext);
    if (uStatus != OpcUa_Good) goto err1;
        
    uStatus = pDecoder->ReadMessage(hDecoderContext, &pMessageType, &pMessage);
    if (uStatus != OpcUa_Good) goto err1;

    
    OpcUa_BrowseRequest* ppReq = (OpcUa_BrowseRequest *) pMessage;
    if (pMessage && pMessageType && pMessageType->BinaryEncodingTypeId == OpcUaId_BrowseRequest_Encoding_DefaultBinary) {
        OpcUa_Int32 nResults;
       
        OpcUa_BrowseRequest* pReq = (OpcUa_BrowseRequest *) pMessage;
        OpcUa_ResponseHeader ResponseHeader;

        OpcUa_Int32 nDiagInfo;
        OpcUa_DiagnosticInfo * pDiagInfo;
        OpcUa_BrowseResult *pResults;
        
        my_Browse(1, 1, &pReq->RequestHeader, &pReq->View, pReq->RequestedMaxReferencesPerNode, pReq->NoOfNodesToBrowse, pReq->NodesToBrowse,
            &ResponseHeader,
            &nResults,
            &pResults,
            &nDiagInfo,
            &pDiagInfo);

        OpcUa_DiagnosticInfo_Clear(pDiagInfo);
        OpcUa_ResponseHeader_Clear(&ResponseHeader);
    }

    if (pMessage && pMessageType && pMessageType->BinaryEncodingTypeId == OpcUaId_ReadRequest_Encoding_DefaultBinary) {
        OpcUa_ResponseHeader ResponseHeader;
        OpcUa_Int32 nResults;
        OpcUa_ReadRequest *pReq = (OpcUa_ReadRequest *) pMessage;
        OpcUa_DataValue *pResults;
        OpcUa_Int32 nDiagInfo;
        OpcUa_DiagnosticInfo *pDiagInfo;

        my_Read(1, 1, &pReq->RequestHeader, pReq->MaxAge, pReq->TimestampsToReturn, pReq->NodesToRead, pReq->NodesToRead,
            &ResponseHeader,
            &nResults,
            &pResults,
            &nDiagInfo,
            &pDiagInfo
        );
        
        OpcUa_DiagnosticInfo_Clear(pDiagInfo);
        OpcUa_ResponseHeader_Clear(&ResponseHeader);
    }

    if (pMessage && pMessageType && pMessageType->BinaryEncodingTypeId == OpcUaId_FindServersRequest_Encoding_DefaultBinary) {
        OpcUa_Int32 nResults;
        OpcUa_FindServersRequest *pReq = (OpcUa_FindServersRequest *) pMessage;
        OpcUa_ApplicationDescription * pServers;
        OpcUa_Int32 nServers;
        OpcUa_ResponseHeader ResponseHeader;

        my_FindServers(1, 1, &pReq->RequestHeader, &pReq->EndpointUrl,  pReq->NoOfLocaleIds, pReq->LocaleIds, pReq->NoOfServerUris, pReq->ServerUris, 
            &ResponseHeader,
            &nServers,
            &pServers
          );
    }

    if (pMessage && pMessageType && pMessageType->BinaryEncodingTypeId == OpcUaId_BrowseNextRequest_Encoding_DefaultBinary) {
        OpcUa_Int32 nResults;
        OpcUa_Int32 nDiagInfo;
        OpcUa_BrowseNextRequest* pReq = (OpcUa_BrowseNextRequest *) pMessage;
        OpcUa_ResponseHeader ResponseHeader;

        OpcUa_DiagnosticInfo * pDiagInfo;
        OpcUa_BrowseResult *pResults;
        
        my_BrowseNext(1, 1, &pReq->RequestHeader, 
            pReq->ReleaseContinuationPoints, 
            pReq->NoOfContinuationPoints, 
            pReq->ContinuationPoints,
            &ResponseHeader, 
            &nResults,
            &pResults,
            &nDiagInfo,
            &pDiagInfo);

        OpcUa_DiagnosticInfo_Clear(pDiagInfo);
        OpcUa_ResponseHeader_Clear(&ResponseHeader);
    }
err1:
    if (pMessage) {
        pMessageType->Clear(pMessage);
        OpcUa_Memory_Free(pMessage);
    }
    pDecoder->Close(pDecoder, &hDecoderContext);
    pDecoder->Delete(&pDecoder);
    OpcUa_Stream_Close((OpcUa_Stream*)pInputStream);
    OpcUa_Stream_Delete((OpcUa_Stream**)&pInputStream);
    OpcUa_MessageContext_Clear(&cContext);

    return 0;
err:
    ExitProcess(1);
    return 0;
}

