package app.util;

import dev.samstevens.totp.code.CodeGenerator;
import dev.samstevens.totp.code.CodeVerifier;
import dev.samstevens.totp.code.DefaultCodeGenerator;
import dev.samstevens.totp.code.DefaultCodeVerifier;
import dev.samstevens.totp.code.HashingAlgorithm;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

public class TotpUtil {
	private static final int OTP_CODE_LENGTH = 6;
	private static final int OTP_CODE_LIFETIME = 30; // in seconds
	
	
	public static String generateOtpSecret() {
		SecretGenerator sg = new DefaultSecretGenerator();
		return sg.generate(); // generates 32 characters long secret as per TOTP protocol
	}

	public static String createQrCodeDataUrl(String userId, String secret, String issuer) throws QrGenerationException {
		QrData data = new QrData.Builder()
				.label(userId)
				.secret(secret)
				.issuer(issuer)
				.algorithm(HashingAlgorithm.SHA256)
				.digits(OTP_CODE_LENGTH)
				.period(OTP_CODE_LIFETIME)
				.build();
		
		QrGenerator generator = new ZxingPngQrGenerator();
		byte[] imageData = generator.generate(data);
		String mimeType = generator.getImageMimeType();
		
		String dataUri = getDataUriForImage(imageData, mimeType);
		
		return dataUri;
	}
	
	
	public static boolean otpVerifier(String secret, String otp) {
		TimeProvider timeProvider = new SystemTimeProvider();
		CodeGenerator codeGenerator = new DefaultCodeGenerator(HashingAlgorithm.SHA256);
		CodeVerifier verifier = new DefaultCodeVerifier(codeGenerator, timeProvider);

		// secret = the shared secret for the user
		// code = the code submitted by the user
		return verifier.isValidCode(secret, otp);
	}
}
