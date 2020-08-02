let socket = undefined;

function connect() {
    let address = document.getElementById("address").value;
    console.log("Connecting to: " + address);
    document.getElementById("status").innerHTML = "Connecting...";
    // Create WebSocket connection.
    socket = new WebSocket(address);

    socket.addEventListener("open", function(event) {
        document.getElementById("status").innerHTML = "Socket opened!";
    });

    socket.addEventListener("close", function(event) {
        document.getElementById("status").innerHTML = "Socket closed!";
    })

    // Listen for messages
    socket.addEventListener("message", function (event) {
        console.log("Message from server: ", event.data);
        addMessageToOutput(event.data, "Server");
    });
}

function addMessageToOutput(message, from) {
    let received = document.getElementById("received").innerHTML;
    received = "<b>" + from + ":</b> " + message + "</br> " + received;
    document.getElementById("received").innerHTML = received;
}

function send() {
    let msg = document.getElementById("msg").value;
    socket.send(msg);
    addMessageToOutput(msg, "Client");
    document.getElementById("msg").value = "";
}