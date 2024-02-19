<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TLV Messgae Parser</title>
</head>
<body>

    <h1>TLV Message Parser</h1>

    <form method="get">
        <label for="Message">Enter the message:</label>
        <br/>
        <span style="color:Gray">(e.g. '6F1A840E315041592E5359532E4444463031A5088801025F2D02656E')</span>
        <br/>
        <textarea required value="<?php echo $_GET['tlv_message']?? '' ?>"
        type="text" id="tlv_message" name="tlv_message"
        rows="10" cols="50" ><?php if ( isset($_GET['tlv_message'])) {echo $_GET['tlv_message'];}?></textarea>
        <br/>
        <button type="submit">Parse Message</button>
    </form>

    <?php
    if (isset($_GET['tlv_message'])) {
    
        $tlv_message = $_GET['tlv_message'];
        $parser_arguments = "-m " . $tlv_message;
        $output = [];

        // Use shell_exec to run the Rust command with the tlv_message as argument
        exec("target\\release\\emv_tlv_parser.exe $parser_arguments 2>&1", $output, $returnCode);
        if ($returnCode !== 0) {
            echo '<p>Error parsing message. Return code: ' . $returnCode . '</p>';
            echo '<p>Error output:  </p>';
            echo '<font color="red">' . implode("<br/>", $output) . '</font>';
        } else {
            echo '<h2>Parsed Message:</h2>';
            echo '<pre>' . htmlspecialchars(implode("\n", $output)) . '</pre>';
        }
    }
    ?>

</body>
</html>
