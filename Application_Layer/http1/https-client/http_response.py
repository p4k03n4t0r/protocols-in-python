class Http_Response:
    def __init__(self, conn):
        line = ""
        while True:
            line += conn.recv(1).decode("utf-8")
            if line.endswith("\r\n"):
                break
        self.parse_start_line(line)

        self.headers = {}
        line = ""
        while True:
            line += conn.recv(1).decode("utf-8")
            if line.endswith("\r\n"):
                # remove the line break
                line = line[:len(line) - 2]
                # if the lines is empty, the header section has ended
                if line is "":
                    break
                split_line = line.split(": ", 1)
                line = ""
                self.headers[split_line[0]] = split_line[1]

        if "Transfer-Encoding" in self.headers and self.headers["Transfer-Encoding"] == "chunked":
            self.parse_chunked_body(conn)
        elif "Content-Length" in self.headers:
            self.parse_content_length_body(conn)

    def parse_start_line(self, start_line):
        # split the start line on the first two occurences of a space
        # the part of the second space is all part of the status message
        split_start_line = start_line.split(" ", 2)
        self.http_version = split_start_line[0]
        self.status_code = split_start_line[1]
        self.status_message = split_start_line[2]
    
    def parse_chunked_body(self, conn):
        self.body = ""
        while True:
            length = ""
            while True:
                length += conn.recv(1).decode("utf-8")
                if length.endswith("\r\n"):
                    # remove the line break from the length and parse from hex to int
                    length = int(length[:len(length) - 2], 16)
                    break
                
            # if the length is 0 the body has ended
            if length == 0:
                break

            self.body += self.receive_length(conn, length)

    def parse_content_length_body(self, conn):
        content_length = int(self.headers["Content-Length"])
        
        self.body = self.receive_length(conn, content_length)
    
    def receive_length(self, conn, length):
        BUFFER_SIZE = 4096
        buffer = ""

        while length > 0:
            if length > BUFFER_SIZE:
                length_to_retrieve = BUFFER_SIZE
                length -= BUFFER_SIZE
            else:
                length_to_retrieve = length
                length -= length_to_retrieve
            buffer += conn.recv(length_to_retrieve).decode("utf-8")

        return buffer

