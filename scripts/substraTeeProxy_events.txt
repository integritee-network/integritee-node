// this script can be used in the JavaScript module of the PolkaDotUI
// https://polkadot.js.org/apps/#/js

 // Subscribe to system events via storage
console.log('# Subscribe to system events from substrateeProxy module');
api.query.system.events((events) => {
    // loop through the Vec<EventRecord>
    events.forEach((record) => {
        // extract the phase, event and the event types
        const { event, phase } = record;
        const types = event.typeDef;

         if (event.section == "substrateeProxy") {
            console.log("\n");
            console.log("--- substraTEEProxy event found ---");
            // show what we are busy with
            console.log(event.section + ':' + event.method + '::' + 'phase=' + phase.toString());
            console.log(event.meta.documentation.toString());
            // loop through each of the parameters, displaying the type and data
            event.data.forEach((data, index) => {
                console.log(types[index].type + ';' + data.toString());
            });
        }
    });
});
