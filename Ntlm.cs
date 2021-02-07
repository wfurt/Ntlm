using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;
using System.Formats.Asn1;

namespace System.Net
{
    // Based on https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d-190923.pdf
    public class Ntlm
    {
        public bool Diag = false;

        private static readonly byte[] _header = new byte[] { (byte)'N', (byte)'T', (byte)'L', (byte)'M',
                                                              (byte)'S', (byte)'S',(byte)'P', 0 };
        private static readonly Random Rnd;

        private static readonly Encoding Utf16;

        private const int ChallengeResponseLength = 24;

        private const int HeaderLenght = 8;

        private const int ChallengeLength = 8;

        private const int DigestLength = 16;

        private const string SpnegoOid = "1.3.6.1.5.5.2";

        private const string NtlmOid = "1.3.6.1.4.1.311.2.2.10";

        private enum MessageType : byte
        {
            Negotiate = 1,
            Challenge = 2,
            Authenticate = 3,
        }

        // 2.2.2.5 NEGOTIATE
        [Flags]
        private enum Flags : uint
        {
            NegotiateUnicode = 0x00000001,
            NegotiateOEM = 0x00000002,
            TargetName = 0x00000004,
            NegotiateSign = 0x00000010,
            NegotiateSeal = 0x00000020,
            NegotiateDatagram = 0x00000040,
            NegotiateLMKey = 0x00000080,
            NegotiateNtlm = 0x00000200,
            NegotiateAnonymous = 0x00000800,
            NegotiateDomainSupplied = 0x00001000,
            NegotiateWorkstationSupplied = 0x00002000,
            NegotiateAlwaysSign = 0x00008000,
            TargetTypeDomain = 0x00010000,
            TargetTypeServer = 0x00020000,
            NegotiateNtlm2 = 0x00080000,
            RequestIdenityToken = 0x00100000,
            RequestNonNtSessionKey = 0x00400000,
            NegotiateTargetInfo = 0x00800000,
            NegotiateVersion = 0x01000000,
            Negotiate128 = 0x20000000,
            NegotiateKeyExchange = 0x40000000,
            Negotiate56 = 0x80000000,
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct MessageField
        {
            public ushort Length;
            public ushort MaximumLength;
            public int PayloadOffset;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct MessageHeader
        {
            fixed byte Header[HeaderLenght];
            public MessageType MessageType;
            byte _unused1;
            byte _unused2;
            byte _unused3;
        }

        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct Version
        {
            public byte VersionMajor;
            public byte VersionMinor;
            public ushort ProductBuild;
            private byte _unused4;
            private byte _unused5;
            private byte _unused6;
            public byte CurrentRevision;
        }

        // Type 1 message
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct NegotiateMessage
        {
            public MessageHeader Header;
            public Flags Flags;
            public MessageField DomainName;
            public MessageField WorkStation;
            public Version Version;
        }

        // TYPE 2 message
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct ChallengeMessage
        {
            public MessageHeader Header;
            public MessageField TargetName;
            public Flags Flags;
            public fixed byte ServerChallenge[ChallengeLength];
            private ulong _unused;
            public MessageField TargetInfo;
            public Version Version;
        }

        // TYPE 3 message
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct AuthenticateMessage
        {
            public MessageHeader Header;
            public MessageField LmChallengeResponse;
            public MessageField NtChallengeResponse;
            public MessageField DomainName;
            public MessageField UserName;
            public MessageField Workstation;
            public MessageField EncryptedRandomSessionKey;
            public Flags Flags;
            public Version Version;
            public fixed byte Mic[16];
            // Payload with fixed space for LN and NTLM responces
            public fixed byte LmResponse[ChallengeResponseLength];  // hash + client challenge.
        }

        // Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
        [StructLayout(LayoutKind.Sequential)]
        private unsafe struct NtChallengeResponse
        {
            public fixed byte Hmac[DigestLength];
            public byte Responserversion;
            public byte HiResponserversion;
            private byte _reserved1;
            private byte _reserved2;
            private int _reserverd3;
            public long Time;
            public fixed byte ClientChallenge[ChallengeLength];
            private int _reserverd4;
            private int _reserverd5;
        }

        // rfc4178
        private enum NegotiationToken
        {
            NegTokenInit = 0,
            NegTokenResp = 1
        }

        private enum NegTokenInit
        {
            MechTypes = 0,
            ReqFlags = 1,
            MechToken = 2,
            MechListMIC = 3
        }

        private enum NegTokenResp
        {
            NegState = 0,
            SupportedMech = 1,
            ResponseToken = 2,
            MechListMIC = 3
        }

        private enum NegState
        {
            Unknown = -1,           // Internal. Not in RFC.
            AcceptCompleted = 0,
            AcceptIncomplete = 1,
            Reject = 2,
            RequiestMic = 3
        }

        private unsafe struct spnego
        {
            public fixed byte oid[6];
            public fixed byte sequenceof[2];
        }

        private readonly NetworkCredential _nc;
        private static readonly byte[] s_workstation;

        static Ntlm()
        {
            s_workstation = Encoding.Unicode.GetBytes(Environment.MachineName);
            Rnd = new Random();
            Utf16 = new UnicodeEncoding();
        }

        public Ntlm(NetworkCredential credentials)
        {
            _nc = credentials;
        }

        public static string FlagsEnumToString<T>(Enum e)
        {
            const string Separator = ", ";
            var str = new StringBuilder();

            foreach (object i in Enum.GetValues(typeof(T)))
            {
                if (IsExactlyOneBitSet((uint)i) &&
                    e.HasFlag((Enum)i))
                {
                    str.Append((T)i + Separator);
                }
            }

            if (str.Length > 0)
            {
                str.Length -= Separator.Length;
            }

            return str.ToString();
        }

        static bool IsExactlyOneBitSet(uint i)
        {
            return i != 0 && (i & (i - 1)) == 0;
        }

        public unsafe string CreateNegotiateMessage(bool spnego = false)
        {
            Debug.Assert(HeaderLenght == _header.Length);

            Span<byte> asBytes = stackalloc byte[sizeof(NegotiateMessage)];
            Span<NegotiateMessage> message = MemoryMarshal.Cast<byte, NegotiateMessage>(asBytes);

            asBytes.Clear();
            _header.CopyTo(asBytes);
            message[0].Header.MessageType = MessageType.Negotiate;
            message[0].Flags = Flags.NegotiateNtlm2 | Flags.NegotiateUnicode | Flags.TargetName | Flags.TargetTypeServer | Flags.NegotiateAlwaysSign;

            if (!spnego)
            {
                return "NTLM " + Convert.ToBase64String(asBytes, Base64FormattingOptions.None);
            }

            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            using (writer.PushSequence(new Asn1Tag(TagClass.Application, 0)))
            {
                writer.WriteObjectIdentifier(SpnegoOid);

                // NegTokenInit::= SEQUENCE {
                //    mechTypes[0] MechTypeList,
                //    reqFlags[1] ContextFlags OPTIONAL,
                //       --inherited from RFC 2478 for backward compatibility,
                //      --RECOMMENDED to be left out
                //    mechToken[2] OCTET STRING  OPTIONAL,
                //    mechListMIC[3] OCTET STRING  OPTIONAL,
                //    ...
                // }
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, (int)NegotiationToken.NegTokenInit)))
                {
                    writer.PushSequence();

                    // MechType::= OBJECT IDENTIFIER
                    //    -- OID represents each security mechanism as suggested by
                    //   --[RFC2743]
                    //
                    // MechTypeList::= SEQUENCE OF MechType
                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, (int)NegTokenInit.MechTypes)))
                    {
                        writer.PushSequence();
                        writer.WriteObjectIdentifier(NtlmOid);
                        writer.PopSequence();
                    }

                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, (int)NegTokenInit.MechToken)))
                    {
                        writer.WriteOctetString(asBytes);
                    }

                    writer.PopSequence();
                }
            }

            return "Negotiate " + Convert.ToBase64String(writer.Encode());
        }

        private unsafe int GetFieldLength(MessageField field)
        {
            ReadOnlySpan<byte> span = MemoryMarshal.Cast<MessageField, byte>(new ReadOnlySpan<MessageField>(&field, sizeof(MessageField)));
            return BinaryPrimitives.ReadInt16LittleEndian(span);
        }

        private unsafe int GetFieldOffset(MessageField field)
        {
            ReadOnlySpan<byte> span = MemoryMarshal.Cast<MessageField, byte>(new ReadOnlySpan<MessageField>(&field, sizeof(MessageField)));
            return BinaryPrimitives.ReadInt16LittleEndian(span.Slice(4));
        }

        private ReadOnlySpan<byte> GetField(MessageField field, ReadOnlySpan<byte> payload)
        {
            int offset = GetFieldOffset(field);
            int length = GetFieldOffset(field);

            if (length == 0 || offset + length > payload.Length)
            {
                return ReadOnlySpan<byte>.Empty;
            }

            return payload.Slice(GetFieldOffset(field), GetFieldLength(field));
        }

        private unsafe void SetField(ref MessageField field, int length, int offset)
        {
            fixed (void* ptr = &field)
            {
                Span<byte> span = new Span<byte>(ptr, sizeof(MessageField));
                BinaryPrimitives.WriteInt16LittleEndian(span, (short)length);
                BinaryPrimitives.WriteInt16LittleEndian(span.Slice(2), (short)length);
                BinaryPrimitives.WriteInt32LittleEndian(span.Slice(4), offset);
            }
        }

        private  int AddToPayload(ref MessageField field, ReadOnlySpan<byte> data, ref Span<byte> payload, int offset)
        {
            SetField(ref field, data.Length, offset);
            data.CopyTo(payload);
            payload = payload.Slice(data.Length);

            return data.Length;
        }

        private int AddToPayload(ref MessageField field, string data, ref Span<byte> payload, int offset)

        {
            byte[] bytes = Encoding.Unicode.GetBytes(data);
            return AddToPayload(ref field, bytes, ref payload, offset);
        }

        // Section 3.3.2
        // Define NTOWFv2(Passwd, User, UserDom) as HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf(Uppercase(User),
        // UserDom ) ) )
        // EndDefine
        private byte[] makeNtlm2Hash(string domain, string userName, string password)
        {
            byte[] pwHash = new byte[DigestLength];
            byte[] pwBytes = Utf16.GetBytes(_nc.Password);

            Md4.Hash(pwHash, pwBytes);
            HMACMD5 hmac = new HMACMD5(pwHash);

            // strangely, user is upper case, domain is not.
            byte[] blob = Utf16.GetBytes(String.Concat(userName.ToUpper(), domain));

            return hmac.ComputeHash(blob);
        }

        // Section 3.3.2
        //
        // Set LmChallengeResponse to ConcatenationOf(
        //                              HMAC_MD5(ResponseKeyLM, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, ClientChallenge)),
        //                              ClientChallenge )
        private int makeLm2ChallengeResponse(byte[] lm2Hash, ReadOnlySpan<byte> serverChallenge, Span<byte> clientChallenge, ref Span<byte> responseAsBytes)
        {
            Debug.Assert(serverChallenge.Length == ChallengeLength);
            Debug.Assert(clientChallenge.Length == ChallengeLength);
            Debug.Assert(lm2Hash.Length == DigestLength);

            Span<AuthenticateMessage> response = MemoryMarshal.Cast<byte, AuthenticateMessage>(responseAsBytes);

            // Get server and client nonce
            Span<byte> blob = stackalloc byte[16];
            serverChallenge.CopyTo(blob);
            clientChallenge.CopyTo(blob.Slice(ChallengeLength));

            Span<byte> lmResponse = responseAsBytes.Slice((int)Marshal.OffsetOf(typeof(AuthenticateMessage), "LmResponse"), ChallengeResponseLength);

            HMACMD5 hmac = new HMACMD5(lm2Hash);
            bool result = hmac.TryComputeHash(blob, lmResponse, out int bytes);
            if (!result ||  bytes != DigestLength)
            {
                return 0;
            }

            clientChallenge.CopyTo(lmResponse.Slice(DigestLength));
            SetField(ref response[0].LmChallengeResponse, ChallengeResponseLength, (int)Marshal.OffsetOf(typeof(AuthenticateMessage), "LmResponse"));

            return ChallengeResponseLength;
        }

        // Section 3.3.2
        // 
        // Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
        // Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, temp))
        // Set NtChallengeResponse to ConcatenationOf(NTProofStr, temp)
        private unsafe int makeNtlm2ChallengeResponse(byte[] lm2Hash, ReadOnlySpan<byte> serverChallenge, Span<byte> clientChallenge, ReadOnlySpan<byte> serverInfo, ref MessageField field, ref Span<byte> payload)
        {
            Debug.Assert(serverChallenge.Length == ChallengeLength);
            Debug.Assert(clientChallenge.Length == ChallengeLength);
            Debug.Assert(lm2Hash.Length == DigestLength);


            Span<byte> blob = payload.Slice(0, sizeof(NtChallengeResponse) + serverInfo.Length);
            Span <NtChallengeResponse> temp = MemoryMarshal.Cast<byte, NtChallengeResponse>(blob.Slice(0, sizeof(NtChallengeResponse)));
                       
            temp[0].HiResponserversion = 1;
            temp[0].Responserversion = 1;
            temp[0].Time = DateTime.Now.Ticks;

            int offset = (int)Marshal.OffsetOf(typeof(NtChallengeResponse), "ClientChallenge");
            clientChallenge.CopyTo(blob.Slice(offset, ChallengeLength));

            offset += ChallengeLength + 4; // challengeLength + Z4
            serverInfo.CopyTo(blob.Slice(offset));

            // We will prepend server chalenge for purpose of calculating NTProofStr
            // It will be overriten later.
            serverChallenge.CopyTo(blob.Slice(ChallengeLength, ChallengeLength));

            Span<byte> NTProofStr = stackalloc byte[DigestLength];
            HMACMD5 hmac = new HMACMD5(lm2Hash);
            bool result = hmac.TryComputeHash(blob.Slice(ChallengeLength), NTProofStr, out int bytes);
            if (!result || bytes != DigestLength)
            {
                return 0;
            }

            // we created temp part in place where it needs to be.
            // now we need to prepend it with calculated hmac.
            // Write first 16 bytes, overiding challengeLength part.
            NTProofStr.CopyTo(blob);
            SetField(ref field, blob.Length, sizeof(AuthenticateMessage));

            payload = payload.Slice(blob.Length);
            return blob.Length;
        }

        public string ProcessChallenge(AuthenticationHeaderValue header)
        {
            if (StringComparer.OrdinalIgnoreCase.Equals(header.Scheme, "NTLM"))
            {
                return ProcessNtlmChallenge(header.Parameter);
            }
            else if (StringComparer.OrdinalIgnoreCase.Equals(header.Scheme, "Negotiate"))
            {
                return ProcessNegotiateChallenge(header.Parameter);
            }

            return string.Empty;
        }

        public string ProcessNtlmChallenge(string challenge)
        {
            if (Diag)
            {
                Console.WriteLine("NTLM challenge: {0}", challenge);
            }

            byte[] data = Convert.FromBase64String(challenge);
            return "NTLM " + Convert.ToBase64String(ProcessChallengeMessage(data), Base64FormattingOptions.None);
        }

        public unsafe string ProcessNegotiateChallenge(string challengeString)
        {
            NegState state = NegState.Unknown;
            string mech = null;
            byte[] blob = null;

            byte[] data = Convert.FromBase64String(challengeString);
            AsnReader reader = new AsnReader(data, AsnEncodingRules.DER);
            AsnReader challengeReader = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, (int)NegotiationToken.NegTokenResp));

            // NegTokenResp::= SEQUENCE {
            //    negState[0] ENUMERATED {
            //        accept - completed(0),
            //        accept - incomplete(1),
            //        reject(2),
            //        request - mic(3)
            //    } OPTIONAL,
            // --REQUIRED in the first reply from the target
            //    supportedMech[1] MechType OPTIONAL,
            // --present only in the first reply from the target
            // responseToken[2] OCTET STRING  OPTIONAL,
            // mechListMIC[3] OCTET STRING  OPTIONAL,
            // ...
            // }

            challengeReader = challengeReader.ReadSequence();
            while (challengeReader.HasData)
            {
                Asn1Tag tag = challengeReader.PeekTag();
                if (tag.TagClass == TagClass.ContextSpecific)
                {
                    NegTokenResp dataType = (NegTokenResp)tag.TagValue;
                    AsnReader specificValue = new AsnReader(challengeReader.PeekContentBytes(), AsnEncodingRules.DER);

                    switch (dataType)
                    {
                        case NegTokenResp.NegState:
                            state = specificValue.ReadEnumeratedValue<NegState>();
                            break;
                        case NegTokenResp.SupportedMech:
                            mech = specificValue.ReadObjectIdentifier();
                            break;
                        case NegTokenResp.ResponseToken:
                            blob = specificValue.ReadOctetString();
                            break;
                        default:
                            // Ignore everything else
                            break;
                    }
                }

                challengeReader.ReadEncodedValue();
            }

            if (Diag)
            {
                Console.WriteLine("Negotiate challenege: {0} - {1} in {2}", challengeString, mech, state);
            }

            // Mechanism should be set on first message. That means always
            // as NTLM has only one challenege message.
            if (!NtlmOid.Equals(mech))
            {
                throw new NotSupportedException($"'{mech}' mechanism is not supported");
            }


            if (state != NegState.Unknown && state != NegState.AcceptIncomplete)
            {
                // If state was set, it should be AcceptIncomplete for us to proseed.  
                return "";
            }

            if (blob?.Length > 0)
            {
                // Process decoded NTLM blob.
                byte[] response = ProcessChallengeMessage(blob);
                if (response?.Length > 0)
                {
                    AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);

                    using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, (int)NegotiationToken.NegTokenResp)))
                    {
                        writer.PushSequence();
                        using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, (int)NegTokenInit.MechToken)))
                        {
                            writer.WriteOctetString(response);
                        }

                        writer.PopSequence();
                    }
                    
                    return "Negotiate " + Convert.ToBase64String(writer.Encode(), Base64FormattingOptions.None);
                }
            }

            return "";
        }

        // This gets decoded byte blob and returns response in binary form.
        private unsafe byte[] ProcessChallengeMessage(byte[] blob)
        {
            ReadOnlySpan<byte> asBytes = new ReadOnlySpan<byte>(blob);
            ReadOnlySpan<ChallengeMessage> challengeMessage = MemoryMarshal.Cast<byte, ChallengeMessage>(asBytes.Slice(0, sizeof(ChallengeMessage)));

            // Verify message type and signature 
            if (challengeMessage[0].Header.MessageType != MessageType.Challenge ||
                !_header.AsSpan().SequenceEqual(asBytes.Slice(0, _header.Length)))
            {
                return null;
            }

            Flags flags = (Flags)BinaryPrimitives.ReadInt32LittleEndian(asBytes.Slice((int)Marshal.OffsetOf(typeof(ChallengeMessage), "Flags"), 4));
            ReadOnlySpan<byte> targetName = GetField(challengeMessage[0].TargetName, asBytes);
            if (Diag)
            {
                string target = Utf16.GetString(targetName);
                Console.WriteLine("Get challenge from '{0}' with 0x{1:x} ({2}) flags", target, flags, FlagsEnumToString<Flags>(flags));
            }

            if (((flags & Flags.NegotiateNtlm2) != Flags.NegotiateNtlm2) ||
                ((flags & Flags.NegotiateTargetInfo) != Flags.NegotiateTargetInfo))
            {
                throw new NotSupportedException("Only NTLNv2 is supported");
            }

            ReadOnlySpan<byte> targetInfo = GetField(challengeMessage[0].TargetInfo, asBytes);

            if (Diag && targetInfo.Length > 0)
            {
                ReadOnlySpan<byte> info = targetInfo;
                while (info.Length >= 4)
                {
                    byte ID = info[0];
                    byte l1 = info[2];
                    byte l2 = info[3];
                    int length = (l2 << 8) + l1;

                    Console.WriteLine("Got ID {0} with {1} len", ID, length);

                    if (ID == 0)
                    {
                        Console.WriteLine("EOF on AV PAIRS reached!");
                        break;
                    }

                    if (4 + length > info.Length)
                    {
                        Console.WriteLine("got field {0} with Len {1} while only {2} remaining", ID, length, info.Length);
                        break;
                    }

                    info = info.Slice(length + 4);
                }
            }
            
            int responseLength = sizeof(AuthenticateMessage) + sizeof(NtChallengeResponse) + targetInfo.Length +
                                 (_nc.UserName.Length + _nc.Domain.Length) * 2 + s_workstation.Length;
            
            byte[] responseBytes = new byte[responseLength];
            Span<byte> responseAsSpan = new Span<byte>(responseBytes);
            Span<AuthenticateMessage> response = MemoryMarshal.Cast<byte, AuthenticateMessage>(responseAsSpan.Slice(0, sizeof(AuthenticateMessage)));

            // variable fields
            Span<byte> payload = responseAsSpan.Slice(sizeof(AuthenticateMessage));
            int payloadOffset = sizeof(AuthenticateMessage);

            responseAsSpan.Clear();
            _header.CopyTo(responseAsSpan);

            // TBD calculate flags.
            response[0].Header.MessageType = MessageType.Authenticate;
            response[0].Flags = Flags.NegotiateNtlm | Flags.NegotiateNtlm2 | Flags.NegotiateUnicode | Flags.TargetName | Flags.TargetTypeServer | Flags.NegotiateTargetInfo;

            // Calculate hash for hmac - same for lm2 and ntlm2
            byte[] ntlm2hash = makeNtlm2Hash(_nc.Domain, _nc.UserName, _nc.Password);

            // Get random bytes for client challenge
            byte[] clientChallenge = new byte[ChallengeLength];
            Rnd.NextBytes(clientChallenge);

            // Create LM2 response.
            ReadOnlySpan<byte> serverChallenge = asBytes.Slice(24, 8);
            makeLm2ChallengeResponse(ntlm2hash, serverChallenge, clientChallenge, ref responseAsSpan);

            // Create NTLM2 response 
            payloadOffset += makeNtlm2ChallengeResponse(ntlm2hash, serverChallenge, clientChallenge, targetInfo, ref response[0].NtChallengeResponse, ref payload);

            payloadOffset += AddToPayload(ref response[0].UserName, _nc.UserName, ref payload, payloadOffset);
            payloadOffset += AddToPayload(ref response[0].DomainName, _nc.Domain, ref payload, payloadOffset);
            AddToPayload(ref response[0].Workstation, s_workstation, ref payload, payloadOffset);

            return responseBytes;
        }
    }
}
