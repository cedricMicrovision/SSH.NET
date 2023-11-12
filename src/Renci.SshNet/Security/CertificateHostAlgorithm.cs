#nullable enable
using System;

using Renci.SshNet.Security.Cryptography;

namespace Renci.SshNet.Security
{
    /// <summary>
    /// Implements certificate support for host algorithm.
    /// </summary>
    public class CertificateHostAlgorithm : KeyHostAlgorithm
    {
        /// <summary>
        /// The <see cref="ConnectionInfo"/> instance used in this connection.
        /// This will be used to retrieve a <see cref="KeyHostAlgorithm"/> in order to verify
        /// the signature within the certificate.
        /// </summary>
        private readonly ConnectionInfo? _connectionInfo;

        /// <summary>
        /// Gets certificate used in this host key algorithm.
        /// </summary>
        public Certificate Certificate { get; }

        /// <summary>
        /// Gets the encoded bytes of the certificate.
        /// </summary>
        public override byte[] Data
        {
            get { return Certificate.Bytes; }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateHostAlgorithm"/> class.
        /// </summary>
        /// <param name="name">The algorithm identifier.</param>
        /// <param name="key"><inheritdoc cref="KeyHostAlgorithm.Key" path="/summary"/></param>
        /// <param name="certificate">The certificate which certifies <paramref name="key"/>.</param>
        public CertificateHostAlgorithm(string name, Key key, Certificate certificate)
            : base(name, key)
        {
            Certificate = certificate;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateHostAlgorithm"/> class.
        /// </summary>
        /// <param name="name">The algorithm identifier.</param>
        /// <param name="key"><inheritdoc cref="KeyHostAlgorithm.Key" path="/summary"/></param>
        /// <param name="certificate">The certificate which certifies <paramref name="key"/>.</param>
        /// <param name="digitalSignature"><inheritdoc cref="KeyHostAlgorithm.DigitalSignature" path="/summary"/></param>
        public CertificateHostAlgorithm(string name, Key key, Certificate certificate, DigitalSignature digitalSignature)
            : base(name, key, digitalSignature)
        {
            Certificate = certificate;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateHostAlgorithm"/> class.
        /// </summary>
        /// <param name="name">The algorithm identifier.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="connectionInfo"><inheritdoc cref="_connectionInfo" path="/summary"/></param>
        public CertificateHostAlgorithm(string name, Certificate certificate, ConnectionInfo connectionInfo)
            : base(name, certificate.Key)
        {
            Certificate = certificate;
            _connectionInfo = connectionInfo;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateHostAlgorithm"/> class.
        /// </summary>
        /// <param name="name">The algorithm identifier.</param>
        /// <param name="certificate">The certificate.</param>
        /// <param name="digitalSignature"><inheritdoc cref="KeyHostAlgorithm.DigitalSignature" path="/summary"/></param>
        /// <param name="connectionInfo"><inheritdoc cref="_connectionInfo" path="/summary"/></param>
        public CertificateHostAlgorithm(string name, Certificate certificate, DigitalSignature digitalSignature, ConnectionInfo connectionInfo)
            : base(name, certificate.Key, digitalSignature)
        {
            Certificate = certificate;
            _connectionInfo = connectionInfo;
        }

        /// <summary>
        /// Verifies the signature.
        /// </summary>
        /// <param name="data">The data to verify the signature against.</param>
        /// <param name="signature">The signature blob.</param>
        /// <returns>
        /// <see langword="true"/> if <paramref name="signature"/> is the result of signing <paramref name="data"/>
        /// with the corresponding private key to <see cref="Certificate"/>, and <see cref="Certificate"/>
        /// is valid with respect to its signature therein as signed by the certificate authority.
        /// </returns>
        public override bool VerifySignature(byte[] data, byte[] signature)
        {
            // Validate the session signature against the public key as normal.

            if (!base.VerifySignature(data, signature))
            {
                return false;
            }

            // Validate the certificate (i.e. the signature contained within) against
            // the CA public key (also contained in the certificate).

            var certSignatureData = new SignatureKeyData();
            certSignatureData.Load(Certificate.Signature);

            if (_connectionInfo is null)
            {
                throw new InvalidOperationException($"Invalid usage of {nameof(CertificateHostAlgorithm)}.{nameof(VerifySignature)}. " +
                    $"Use a constructor which has a {nameof(ConnectionInfo)} parameter.");
            }

            return _connectionInfo.HostKeyAlgorithms.TryGetValue(certSignatureData.AlgorithmName, out var certSigAlgFactory) &&
                certSigAlgFactory(Certificate.SignatureKey).VerifySignature(Certificate.BytesForSignature, certSignatureData.Signature);
        }
    }

    // TODO
    // unit tests on Certificate (validate values)
    // probably change unit tests on KeyHostAlgorithm.Validate
    // unit tests on CertificateHostAlgorithm
    // integration tests
    //     auth: TrustedUserCAKeys and clear authorized_keys
    //     host: HostKeyEvent args stuff
    // xmldoc
}
