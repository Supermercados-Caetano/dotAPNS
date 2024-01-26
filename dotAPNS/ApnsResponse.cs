using Newtonsoft.Json;

namespace dotAPNS
{
    public class ApnsResponse
    {
        public ApnsResponseReason Reason { get; }
        public string? ReasonString { get; }
        public bool IsSuccessful { get; }
        public string? Id { get; set; }

        [JsonConstructor]
        ApnsResponse(ApnsResponseReason reason, string? reasonString, bool isSuccessful, string? id = null)
        {
            Reason = reason;
            ReasonString = reasonString;
            IsSuccessful = isSuccessful;
            Id = id;
        }

        public static ApnsResponse Successful(string? id = null) => new ApnsResponse(ApnsResponseReason.Success, null, true, id);

        public static ApnsResponse Error(ApnsResponseReason reason, string reasonString, string? id = null) => new ApnsResponse(reason, reasonString, false, id);
    }
}