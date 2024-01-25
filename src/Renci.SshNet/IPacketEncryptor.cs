using System;

namespace Renci.SshNet
{
    /// <summary>
    /// Represents the functionality for encrypting SSH binary payloads
    /// for the client-to-server message direction.
    /// </summary>
    public interface IPacketEncryptor
        : IDisposable
    {
        /// <summary>
        /// Gets x.
        /// </summary>
        byte PaddingMultiplier { get; }

        /// <summary>
        /// Serializes the message to a binary packet ready to be sent to the server.
        /// </summary>
        /// <param name="packetData">The unencrypted packet.</param>
        /// <returns>The serialized message as a byte array.</returns>
        byte[] Encrypt(byte[] packetData);
    }

    /// <summary>
    /// Represents the functionality for decrypting SSH binary payloads
    /// for the server-to-client message direction.
    /// </summary>
    public interface IPacketDecryptor
        : IDisposable
    {
        /// <summary>
        /// Gets x.
        /// </summary>
        byte PaddingMultiplier { get; }

        uint ReadPacketLength(byte[] packetData);

        /// <summary>
        /// Serializes the message to a binary packet ready to be sent to the server.
        /// </summary>
        /// <param name="packetData">The unencrypted packet.</param>
        /// <returns>The serialized message as a byte array.</returns>
        byte[] Encrypt(byte[] packetData);
    }
}
