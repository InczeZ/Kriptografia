package message;

import lombok.Getter;

public class MyMessage {
    public String message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt"
            + "ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi"
            + "ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum"
            + "dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia"
            + "deserunt mollit anim id est laborum.";

    @Getter
    public String constructedMessage;

    public String getMessage() {
        return message.repeat(3);
    }

    public void constructMessage (String newPart) {
        if (constructedMessage == null) {
            constructedMessage = newPart;
        } else {
            constructedMessage = constructedMessage + newPart;
        }
    }
}
