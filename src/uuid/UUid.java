package uuid;

import java.util.UUID;

public class UUid {
	public static String getUDID(){
		return UUID.randomUUID().toString().replace("-", "");
	}
}
